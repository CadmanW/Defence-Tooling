// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RB2_AUTH_BPF 1
#include "auth_pam.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// XXX: targeting linux kernel 5.8+, to target 5.5+ instead move to perf instead
// of a ringbuffer and use old probe read functions

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_start_pending);
} start_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_set_item_pending);
} set_item_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_get_user_pending);
} get_user_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_call_pending);
} auth_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_call_pending);
} acct_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_call_pending);
} open_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_call_pending);
} close_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, struct rb2_auth_call_pending);
} end_pending SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, struct rb2_auth_txn_key);
  __type(value, struct rb2_auth_txn_state);
} txns SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct rb2_auth_txn_state);
} scratch_state SEC(".maps");

static __always_inline __u32 current_tid(void) {
  return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline __u32 current_tgid(void) {
  return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline void zero_string(char *dst, __u32 size) {
  __builtin_memset(dst, 0, size);
}

static __always_inline void read_user_string(char *dst, __u32 size,
                                             const void *ptr) {
  long rc;

  zero_string(dst, size);
  if (!ptr) {
    return;
  }

  rc = bpf_probe_read_user_str(dst, size, ptr);
  if (rc < 0) {
    zero_string(dst, size);
  }
}

static __always_inline void copy_inline_string(char *dst, const char *src,
                                               __u32 size) {
  __builtin_memcpy(dst, src, size);
}

static __always_inline void
fill_event_from_state(struct rb2_auth_event *event,
                      const struct rb2_auth_txn_state *state) {
  if (!state) {
    return;
  }

  copy_inline_string(event->service, state->service, sizeof(event->service));
  copy_inline_string(event->requested_user, state->requested_user,
                     sizeof(event->requested_user));
  copy_inline_string(event->resolved_user, state->resolved_user,
                     sizeof(event->resolved_user));
  copy_inline_string(event->rhost, state->rhost, sizeof(event->rhost));
  copy_inline_string(event->ruser, state->ruser, sizeof(event->ruser));
  copy_inline_string(event->tty, state->tty, sizeof(event->tty));
  event->auth_rc = state->auth_rc;
  event->acct_rc = state->acct_rc;
  event->session_rc = state->session_rc;
  event->session_opened = state->session_opened;
}

static __always_inline void emit_event(__u64 pamh, enum rb2_auth_stage stage,
                                       int rc,
                                       const struct rb2_auth_txn_state *state) {
  struct rb2_auth_event *event;
  struct task_struct *task;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return;
  }

  __builtin_memset(event, 0, sizeof(*event));
  event->ts_ns = bpf_ktime_get_ns();
  event->pamh = pamh;
  event->pid = current_tgid();
  event->tgid = current_tgid();
  event->audit_loginuid = (__u32)-1;
  event->audit_sessionid = (__u32)-1;
  event->stage = stage;
  event->rc = rc;
  event->auth_rc = RB2_AUTH_RC_UNSET;
  event->acct_rc = RB2_AUTH_RC_UNSET;
  event->session_rc = RB2_AUTH_RC_UNSET;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  task = (struct task_struct *)bpf_get_current_task();
  if (task) {
    if (bpf_core_field_exists(task->loginuid.val)) {
      event->audit_loginuid = BPF_CORE_READ(task, loginuid.val);
    }
    if (bpf_core_field_exists(task->sessionid)) {
      event->audit_sessionid = BPF_CORE_READ(task, sessionid);
    }
  }
  fill_event_from_state(event, state);
  bpf_ringbuf_submit(event, 0);
}

static __always_inline struct rb2_auth_txn_key make_txn_key(__u64 pamh) {
  struct rb2_auth_txn_key key = {
      .tgid = current_tgid(),
      .pamh = pamh,
  };

  return key;
}

static __always_inline struct rb2_auth_txn_state *lookup_state(__u64 pamh) {
  struct rb2_auth_txn_key key = make_txn_key(pamh);

  return bpf_map_lookup_elem(&txns, &key);
}

static __always_inline int save_call_pending(void *map, __u64 pamh) {
  struct rb2_auth_call_pending pending = {
      .pamh = pamh,
  };
  __u32 tid = current_tid();

  return bpf_map_update_elem(map, &tid, &pending, BPF_ANY);
}

SEC("uprobe/pam_start")
int handle_pam_start_enter(struct pt_regs *ctx) {
  struct rb2_auth_start_pending pending = {};
  __u32 tid = current_tid();

  pending.pamh_pp = (__u64)PT_REGS_PARM4(ctx);
  read_user_string(pending.service, sizeof(pending.service),
                   (const void *)PT_REGS_PARM1(ctx));
  read_user_string(pending.requested_user, sizeof(pending.requested_user),
                   (const void *)PT_REGS_PARM2(ctx));

  bpf_map_update_elem(&start_pending, &tid, &pending, BPF_ANY);
  return 0;
}

SEC("uretprobe/pam_start")
int handle_pam_start_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_start_pending *pending;
  struct rb2_auth_txn_state *state;
  __u32 zero = 0;
  __u64 pamh = 0;

  pending = bpf_map_lookup_elem(&start_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = bpf_map_lookup_elem(&scratch_state, &zero);
  if (!state) {
    bpf_map_delete_elem(&start_pending, &tid);
    return 0;
  }
  __builtin_memset(state, 0, sizeof(*state));
  state->auth_rc = RB2_AUTH_RC_UNSET;
  state->acct_rc = RB2_AUTH_RC_UNSET;
  state->session_rc = RB2_AUTH_RC_UNSET;

  if (rc == RB2_PAM_SUCCESS) {
    bpf_probe_read_user(&pamh, sizeof(pamh), (const void *)pending->pamh_pp);
    if (pamh) {
      struct rb2_auth_txn_key key = make_txn_key(pamh);

      copy_inline_string(state->service, pending->service,
                         sizeof(state->service));
      copy_inline_string(state->requested_user, pending->requested_user,
                         sizeof(state->requested_user));
      bpf_map_update_elem(&txns, &key, state, BPF_ANY);
      emit_event(pamh, RB2_AUTH_STAGE_START, rc, state);
    }
  } else {
    copy_inline_string(state->service, pending->service,
                       sizeof(state->service));
    copy_inline_string(state->requested_user, pending->requested_user,
                       sizeof(state->requested_user));
    emit_event(0, RB2_AUTH_STAGE_START, rc, state);
  }

  bpf_map_delete_elem(&start_pending, &tid);
  return 0;
}

SEC("uprobe/pam_set_item")
int handle_pam_set_item_enter(struct pt_regs *ctx) {
  struct rb2_auth_set_item_pending pending = {
      .pamh = (__u64)PT_REGS_PARM1(ctx),
      .item_type = (__s32)PT_REGS_PARM2(ctx),
      .item_ptr = (__u64)PT_REGS_PARM3(ctx),
  };
  __u32 tid = current_tid();

  bpf_map_update_elem(&set_item_pending, &tid, &pending, BPF_ANY);
  return 0;
}

SEC("uretprobe/pam_set_item")
int handle_pam_set_item_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_set_item_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&set_item_pending, &tid);
  if (!pending) {
    return 0;
  }

  if (rc == RB2_PAM_SUCCESS) {
    state = lookup_state(pending->pamh);
    if (state) {
      if (pending->item_type == RB2_PAM_SERVICE) {
        read_user_string(state->service, sizeof(state->service),
                         (const void *)pending->item_ptr);
      } else if (pending->item_type == RB2_PAM_USER) {
        read_user_string(state->requested_user, sizeof(state->requested_user),
                         (const void *)pending->item_ptr);
      } else if (pending->item_type == RB2_PAM_RHOST) {
        read_user_string(state->rhost, sizeof(state->rhost),
                         (const void *)pending->item_ptr);
      } else if (pending->item_type == RB2_PAM_RUSER) {
        read_user_string(state->ruser, sizeof(state->ruser),
                         (const void *)pending->item_ptr);
      } else if (pending->item_type == RB2_PAM_TTY) {
        read_user_string(state->tty, sizeof(state->tty),
                         (const void *)pending->item_ptr);
      }
    }
  }

  bpf_map_delete_elem(&set_item_pending, &tid);
  return 0;
}

SEC("uprobe/pam_get_user")
int handle_pam_get_user_enter(struct pt_regs *ctx) {
  struct rb2_auth_get_user_pending pending = {
      .pamh = (__u64)PT_REGS_PARM1(ctx),
      .user_pp = (__u64)PT_REGS_PARM2(ctx),
  };
  __u32 tid = current_tid();

  bpf_map_update_elem(&get_user_pending, &tid, &pending, BPF_ANY);
  return 0;
}

SEC("uretprobe/pam_get_user")
int handle_pam_get_user_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_get_user_pending *pending;
  struct rb2_auth_txn_state *state;
  const char *user_ptr = 0;

  pending = bpf_map_lookup_elem(&get_user_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  if (state && rc == RB2_PAM_SUCCESS) {
    bpf_probe_read_user(&user_ptr, sizeof(user_ptr),
                        (const void *)pending->user_pp);
    read_user_string(state->resolved_user, sizeof(state->resolved_user),
                     (const void *)user_ptr);
  }

  emit_event(pending->pamh, RB2_AUTH_STAGE_GET_USER, rc, state);
  bpf_map_delete_elem(&get_user_pending, &tid);
  return 0;
}

SEC("uprobe/pam_authenticate")
int handle_pam_authenticate_enter(struct pt_regs *ctx) {
  save_call_pending(&auth_pending, (__u64)PT_REGS_PARM1(ctx));
  return 0;
}

SEC("uretprobe/pam_authenticate")
int handle_pam_authenticate_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_call_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&auth_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  if (state) {
    state->auth_rc = rc;
  }
  emit_event(pending->pamh, RB2_AUTH_STAGE_AUTHENTICATE, rc, state);
  bpf_map_delete_elem(&auth_pending, &tid);
  return 0;
}

SEC("uprobe/pam_acct_mgmt")
int handle_pam_acct_mgmt_enter(struct pt_regs *ctx) {
  save_call_pending(&acct_pending, (__u64)PT_REGS_PARM1(ctx));
  return 0;
}

SEC("uretprobe/pam_acct_mgmt")
int handle_pam_acct_mgmt_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_call_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&acct_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  if (state) {
    state->acct_rc = rc;
  }
  emit_event(pending->pamh, RB2_AUTH_STAGE_ACCT_MGMT, rc, state);
  bpf_map_delete_elem(&acct_pending, &tid);
  return 0;
}

SEC("uprobe/pam_open_session")
int handle_pam_open_session_enter(struct pt_regs *ctx) {
  save_call_pending(&open_pending, (__u64)PT_REGS_PARM1(ctx));
  return 0;
}

SEC("uretprobe/pam_open_session")
int handle_pam_open_session_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_call_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&open_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  if (state) {
    state->session_rc = rc;
    state->session_opened = rc == RB2_PAM_SUCCESS;
  }
  emit_event(pending->pamh, RB2_AUTH_STAGE_OPEN_SESSION, rc, state);
  bpf_map_delete_elem(&open_pending, &tid);
  return 0;
}

SEC("uprobe/pam_close_session")
int handle_pam_close_session_enter(struct pt_regs *ctx) {
  save_call_pending(&close_pending, (__u64)PT_REGS_PARM1(ctx));
  return 0;
}

SEC("uretprobe/pam_close_session")
int handle_pam_close_session_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_call_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&close_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  if (state) {
    if (rc == RB2_PAM_SUCCESS) {
      state->session_opened = 0;
    }
  }
  emit_event(pending->pamh, RB2_AUTH_STAGE_CLOSE_SESSION, rc, state);
  bpf_map_delete_elem(&close_pending, &tid);
  return 0;
}

SEC("uprobe/pam_end")
int handle_pam_end_enter(struct pt_regs *ctx) {
  save_call_pending(&end_pending, (__u64)PT_REGS_PARM1(ctx));
  return 0;
}

SEC("uretprobe/pam_end")
int handle_pam_end_exit(struct pt_regs *ctx) {
  __u32 tid = current_tid();
  int rc = (int)PT_REGS_RC(ctx);
  struct rb2_auth_call_pending *pending;
  struct rb2_auth_txn_state *state;

  pending = bpf_map_lookup_elem(&end_pending, &tid);
  if (!pending) {
    return 0;
  }

  state = lookup_state(pending->pamh);
  emit_event(pending->pamh, RB2_AUTH_STAGE_END, rc, state);

  if (pending->pamh) {
    struct rb2_auth_txn_key key = make_txn_key(pending->pamh);

    bpf_map_delete_elem(&txns, &key);
  }

  bpf_map_delete_elem(&end_pending, &tid);
  return 0;
}
