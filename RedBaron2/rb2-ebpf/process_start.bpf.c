// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define ARGS_BUF_SIZE 512
#define MAX_ARGS 32

#define MAX_PATH_COMPONENT_SIZE 32
#define MAX_PATH_COMPONENTS 8
#define TASK_COMM_LEN 16

struct args {
  __u32 argc;              // number of args captured
  __u32 used;              // bytes used in buf
  __u16 off[MAX_ARGS];     // offset into buf for each arg
  __u16 len[MAX_ARGS];     // length (including NUL)
  char buf[ARGS_BUF_SIZE]; // packed NUL-terminated strings
};

struct process_event {
  __u64 timestamp; // ns since system boot
  __s64 ret;

  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 sid;

  __u32 audit_loginuid;
  __u32 audit_sessionid;

  char name[TASK_COMM_LEN];  // comm
  char pname[TASK_COMM_LEN]; // parent comm

  struct args argv;
  char executable[MAX_PATH_COMPONENTS][MAX_PATH_COMPONENT_SIZE]; // split path
  char working_directory[MAX_PATH_COMPONENTS]
                        [MAX_PATH_COMPONENT_SIZE]; // split cwd
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// per-CPU scratch space for building events
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct process_event);
} scratch_event SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 256);
  __type(key, __u64); // pid_tgid
  __type(value, struct args);
} exec_args SEC(".maps");

static __always_inline void extract_argv_ptr(const char *const *argv,
                                             struct args *out);
static __always_inline int
capture_exec_args(struct trace_event_raw_sys_enter *ctx, int argv_index);
static __always_inline int
handle_exec_exit(struct trace_event_raw_sys_exit *ctx);

static __always_inline void extract_argv_ptr(const char *const *argv,
                                             struct args *out) {
  out->argc = 0;
  out->used = 0;

  for (int i = 0; i < MAX_ARGS; i++) {
    const char *argp = NULL;

    if (bpf_probe_read(&argp, sizeof(argp), &argv[i]) < 0)
      break;
    if (!argp)
      break;

    __u32 used = out->used;
    if (used >= ARGS_BUF_SIZE)
      break;

    __u32 remaining = ARGS_BUF_SIZE - used;
    if (remaining < 2)
      break;

    out->off[i] = (__u16)used;

    long n = bpf_probe_read_str(&out->buf[used], remaining, argp);
    if (n < 0)
      break;

    __u32 l = (__u32)n;
    if (l == 0)
      break;
    if (l > remaining)
      l = remaining;

    out->len[i] = (__u16)l;
    out->used = used + l;
    out->argc++;
  }
}

static __always_inline int
capture_exec_args(struct trace_event_raw_sys_enter *ctx, int argv_index) {
  __u32 zero = 0;
  __u64 key = bpf_get_current_pid_tgid();
  const char *const *argv;

  if (argv_index < 0 || argv_index >= 6)
    return 0;

  argv = (const char *const *)ctx->args[argv_index];

  struct process_event *e = bpf_map_lookup_elem(&scratch_event, &zero);
  if (!e)
    return 0;

  __builtin_memset(&e->argv, 0, sizeof(e->argv));
  extract_argv_ptr(argv, &e->argv);
  bpf_map_update_elem(&exec_args, &key, &e->argv, BPF_ANY);

  return 0;
}

/* Walk dentry chain (basename-first order). */
static __always_inline void
extract_dentry_path(struct dentry *dentry,
                    char out[MAX_PATH_COMPONENTS][MAX_PATH_COMPONENT_SIZE]) {
  __builtin_memset(out, 0, MAX_PATH_COMPONENTS * MAX_PATH_COMPONENT_SIZE);

  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    if (!dentry)
      break;

    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == parent)
      break;

    const struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read(out[i], MAX_PATH_COMPONENT_SIZE, d_name.name);
    out[i][MAX_PATH_COMPONENT_SIZE - 1] = 0;

    dentry = parent;
  }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec_enter(struct trace_event_raw_sys_enter *ctx) {
  return capture_exec_args(ctx, 1);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat_enter(struct trace_event_raw_sys_enter *ctx) {
  return capture_exec_args(ctx, 2);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exec_exit(struct trace_event_raw_sys_exit *ctx) {
  return handle_exec_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_execveat_exit(struct trace_event_raw_sys_exit *ctx) {
  return handle_exec_exit(ctx);
}
static __always_inline int
handle_exec_exit(struct trace_event_raw_sys_exit *ctx) {
  __u32 zero = 0;
  __u64 key = bpf_get_current_pid_tgid();

  struct process_event *e = bpf_map_lookup_elem(&scratch_event, &zero);
  if (!e)
    return 0;

  struct args *argv = bpf_map_lookup_elem(&exec_args, &key);

  e->timestamp = bpf_ktime_get_ns();
  e->ret = ctx->ret;

  if (argv)
    __builtin_memcpy(&e->argv, argv, sizeof(*argv));

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  e->pid = BPF_CORE_READ(task, pid);
  e->ppid = BPF_CORE_READ(task, real_parent, pid);

  struct task_struct *parent = BPF_CORE_READ(task, real_parent);
  bpf_core_read(e->pname, sizeof(e->pname), &parent->comm);
  bpf_get_current_comm(&e->name, sizeof(e->name));

  struct dentry *exe_dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);
  if (exe_dentry)
    extract_dentry_path(exe_dentry, e->executable);
  else
    __builtin_memset(e->executable, 0, sizeof(e->executable));

  struct dentry *cwd_dentry = BPF_CORE_READ(task, fs, pwd.dentry);
  if (cwd_dentry)
    extract_dentry_path(cwd_dentry, e->working_directory);
  else
    __builtin_memset(e->working_directory, 0, sizeof(e->working_directory));

  e->uid = BPF_CORE_READ(task, real_cred, uid.val);
  e->audit_loginuid = BPF_CORE_READ(task, loginuid.val);
  e->audit_sessionid = BPF_CORE_READ(task, sessionid);

  int e_sid;
  if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_SID))
    e_sid = bpf_core_enum_value(enum pid_type, PIDTYPE_SID);
  else
    e_sid = PIDTYPE_SID;

  struct pid *spid = BPF_CORE_READ(task, group_leader, signal, pids[e_sid]);
  if (!spid) {
    e->sid = 0;
    goto out;
  }

  u32 nr = 0;
  const struct upid *u =
      ((void *)spid + bpf_core_field_offset(struct pid, numbers));
  bpf_core_read(&nr, sizeof(nr), &u->nr);
  e->sid = nr;

out:
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
  bpf_map_delete_elem(&exec_args, &key);
  return 0;
}
