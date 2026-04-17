// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define RB2_TLS_CAPTURE_MAX 4096

#define RB2_TLS_CALL_OPENSSL_WRITE 1
#define RB2_TLS_CALL_OPENSSL_WRITE_EX 2
#define RB2_TLS_CALL_GNUTLS_SEND 3
#define RB2_TLS_CALL_NSS_WRITE 4
#define RB2_TLS_CALL_NSS_SEND 5

#define RB2_TLS_LIB_OPENSSL 1
#define RB2_TLS_LIB_GNUTLS 2
#define RB2_TLS_LIB_NSS 3

const volatile __u32 max_capture_size = 2048;

struct rb2_tls_pending {
  __u64 conn_ptr;
  __u64 buf_ptr;
  __u64 len_ptr;
  __u64 requested_len;
  __u32 call_kind;
};

struct rb2_tls_event_hdr {
  __u32 pid;
  __u32 tid;
  __u32 uid;
  __u32 library_kind;
  __u64 conn_ptr;
  __u32 plaintext_len;
  __u32 captured_len;
  char comm[TASK_COMM_LEN];
};

struct rb2_tls_event {
  struct rb2_tls_event_hdr hdr;
  __u8 buf[RB2_TLS_CAPTURE_MAX];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_tls_pending);
} pending_writes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct rb2_tls_event);
} event_heap SEC(".maps");

static __always_inline struct rb2_tls_event *get_event_heap(void) {
  const __u32 zero = 0;

  return bpf_map_lookup_elem(&event_heap, &zero);
}

static __always_inline __u32 current_tid(void) {
  return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline __u32 current_pid(void) {
  return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 library_kind_for_call(__u32 call_kind) {
  switch (call_kind) {
  case RB2_TLS_CALL_OPENSSL_WRITE:
  case RB2_TLS_CALL_OPENSSL_WRITE_EX:
    return RB2_TLS_LIB_OPENSSL;
  case RB2_TLS_CALL_GNUTLS_SEND:
    return RB2_TLS_LIB_GNUTLS;
  case RB2_TLS_CALL_NSS_WRITE:
  case RB2_TLS_CALL_NSS_SEND:
    return RB2_TLS_LIB_NSS;
  default:
    return 0;
  }
}

static __always_inline __u32 clamp_capture_len(__u64 plaintext_len) {
  __u32 limit = max_capture_size;

  if (limit == 0)
    limit = 1;
  if (limit > RB2_TLS_CAPTURE_MAX)
    limit = RB2_TLS_CAPTURE_MAX;
  if (plaintext_len < (__u64)limit)
    return (__u32)plaintext_len;
  return limit;
}

static __always_inline int
write_enter_common(__u32 call_kind, const void *conn_ptr, const void *buf_ptr,
                   const void *len_ptr, __u64 requested_len) {
  struct rb2_tls_pending pending = {
      .conn_ptr = (__u64)conn_ptr,
      .buf_ptr = (__u64)buf_ptr,
      .len_ptr = (__u64)len_ptr,
      .requested_len = requested_len,
      .call_kind = call_kind,
  };
  __u32 tid = current_tid();

  bpf_map_update_elem(&pending_writes, &tid, &pending, BPF_ANY);
  return 0;
}

static __always_inline int
resolve_plaintext_len(const struct rb2_tls_pending *pending,
                      struct pt_regs *ctx, __u64 *out_len) {
  long rc = PT_REGS_RC(ctx);

  if (pending->call_kind == RB2_TLS_CALL_OPENSSL_WRITE_EX) {
    __u64 written = 0;

    if (rc <= 0)
      return 0;
    if (pending->len_ptr &&
        bpf_probe_read_user(&written, sizeof(written),
                            (const void *)pending->len_ptr) == 0 &&
        written > 0) {
      *out_len = written;
      return 1;
    }
    return 0;
  }

  if (rc <= 0)
    return 0;
  *out_len = (__u64)rc;
  return 1;
}

static __always_inline int write_exit_common(struct pt_regs *ctx,
                                             __u32 call_kind) {
  __u32 tid = current_tid();
  struct rb2_tls_pending *pending = bpf_map_lookup_elem(&pending_writes, &tid);
  struct rb2_tls_event *event;
  __u64 plaintext_len64 = 0;
  __u32 captured_len = 0;
  __u32 event_size = 0;

  if (!pending)
    return 0;
  if (pending->call_kind != call_kind) {
    bpf_map_delete_elem(&pending_writes, &tid);
    return 0;
  }
  if (!resolve_plaintext_len(pending, ctx, &plaintext_len64) ||
      plaintext_len64 == 0) {
    bpf_map_delete_elem(&pending_writes, &tid);
    return 0;
  }

  captured_len = clamp_capture_len(plaintext_len64);
  event_size = sizeof(event->hdr) + captured_len;

  event = get_event_heap();
  if (!event) {
    bpf_map_delete_elem(&pending_writes, &tid);
    return 0;
  }

  event->hdr.pid = current_pid();
  event->hdr.tid = tid;
  event->hdr.uid = (__u32)bpf_get_current_uid_gid();
  event->hdr.library_kind = library_kind_for_call(call_kind);
  event->hdr.conn_ptr = pending->conn_ptr;
  event->hdr.plaintext_len =
      plaintext_len64 > 0xffffffff ? 0xffffffff : (__u32)plaintext_len64;
  event->hdr.captured_len = 0;
  bpf_get_current_comm(event->hdr.comm, sizeof(event->hdr.comm));

  if (captured_len > 0 && pending->buf_ptr &&
      bpf_probe_read_user(event->buf, captured_len,
                          (const void *)pending->buf_ptr) == 0) {
    event->hdr.captured_len = captured_len;
  }

  bpf_ringbuf_output(&events, event, event_size, 0);
  bpf_map_delete_elem(&pending_writes, &tid);
  return 0;
}

SEC("uprobe/openssl_write")
int handle_openssl_write_enter(struct pt_regs *ctx) {
  return write_enter_common(RB2_TLS_CALL_OPENSSL_WRITE,
                            (const void *)PT_REGS_PARM1(ctx),
                            (const void *)PT_REGS_PARM2(ctx), 0, 0);
}

SEC("uretprobe/openssl_write")
int handle_openssl_write_exit(struct pt_regs *ctx) {
  return write_exit_common(ctx, RB2_TLS_CALL_OPENSSL_WRITE);
}

SEC("uprobe/openssl_write_ex")
int handle_openssl_write_ex_enter(struct pt_regs *ctx) {
  return write_enter_common(
      RB2_TLS_CALL_OPENSSL_WRITE_EX, (const void *)PT_REGS_PARM1(ctx),
      (const void *)PT_REGS_PARM2(ctx), (const void *)PT_REGS_PARM4(ctx),
      (__u64)PT_REGS_PARM3(ctx));
}

SEC("uretprobe/openssl_write_ex")
int handle_openssl_write_ex_exit(struct pt_regs *ctx) {
  return write_exit_common(ctx, RB2_TLS_CALL_OPENSSL_WRITE_EX);
}

SEC("uprobe/gnutls_record_send")
int handle_gnutls_record_send_enter(struct pt_regs *ctx) {
  return write_enter_common(RB2_TLS_CALL_GNUTLS_SEND,
                            (const void *)PT_REGS_PARM1(ctx),
                            (const void *)PT_REGS_PARM2(ctx), 0, 0);
}

SEC("uretprobe/gnutls_record_send")
int handle_gnutls_record_send_exit(struct pt_regs *ctx) {
  return write_exit_common(ctx, RB2_TLS_CALL_GNUTLS_SEND);
}

SEC("uprobe/nss_pr_write")
int handle_nss_pr_write_enter(struct pt_regs *ctx) {
  return write_enter_common(RB2_TLS_CALL_NSS_WRITE,
                            (const void *)PT_REGS_PARM1(ctx),
                            (const void *)PT_REGS_PARM2(ctx), 0, 0);
}

SEC("uretprobe/nss_pr_write")
int handle_nss_pr_write_exit(struct pt_regs *ctx) {
  return write_exit_common(ctx, RB2_TLS_CALL_NSS_WRITE);
}

SEC("uprobe/nss_pr_send")
int handle_nss_pr_send_enter(struct pt_regs *ctx) {
  return write_enter_common(RB2_TLS_CALL_NSS_SEND,
                            (const void *)PT_REGS_PARM1(ctx),
                            (const void *)PT_REGS_PARM2(ctx), 0, 0);
}

SEC("uretprobe/nss_pr_send")
int handle_nss_pr_send_exit(struct pt_regs *ctx) {
  return write_exit_common(ctx, RB2_TLS_CALL_NSS_SEND);
}
