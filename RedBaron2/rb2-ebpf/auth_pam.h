#ifndef RB2_AUTH_PAM_H
#define RB2_AUTH_PAM_H

#ifdef RB2_AUTH_BPF
typedef __u8 rb2_u8;
typedef __u32 rb2_u32;
typedef __u64 rb2_u64;
typedef __s32 rb2_s32;
#else
#include <stdint.h>
typedef uint8_t rb2_u8;
typedef uint32_t rb2_u32;
typedef uint64_t rb2_u64;
typedef int32_t rb2_s32;
#endif

#define RB2_AUTH_STR_LEN 48
#define RB2_AUTH_COMM_LEN 16
#define RB2_AUTH_RC_UNSET (-1000000)

enum rb2_auth_stage {
    RB2_AUTH_STAGE_START = 1,
    RB2_AUTH_STAGE_GET_USER = 2,
    RB2_AUTH_STAGE_AUTHENTICATE = 3,
    RB2_AUTH_STAGE_ACCT_MGMT = 4,
    RB2_AUTH_STAGE_OPEN_SESSION = 5,
    RB2_AUTH_STAGE_CLOSE_SESSION = 6,
    RB2_AUTH_STAGE_END = 7,
};

struct rb2_auth_txn_state {
    char service[RB2_AUTH_STR_LEN];
    char requested_user[RB2_AUTH_STR_LEN];
    char resolved_user[RB2_AUTH_STR_LEN];
    char rhost[RB2_AUTH_STR_LEN];
    char ruser[RB2_AUTH_STR_LEN];
    char tty[RB2_AUTH_STR_LEN];
    rb2_s32 auth_rc;
    rb2_s32 acct_rc;
    rb2_s32 session_rc;
    rb2_u8 session_opened;
};

struct rb2_auth_txn_key {
    rb2_u32 tgid;
    rb2_u64 pamh;
};

struct rb2_auth_event {
    rb2_u64 ts_ns;
    rb2_u64 pamh;
    rb2_u32 pid;
    rb2_u32 tgid;
    rb2_u32 audit_loginuid;
    rb2_u32 audit_sessionid;
    rb2_s32 stage;
    rb2_s32 rc;
    rb2_s32 auth_rc;
    rb2_s32 acct_rc;
    rb2_s32 session_rc;
    rb2_u8 session_opened;
    char comm[RB2_AUTH_COMM_LEN];
    char service[RB2_AUTH_STR_LEN];
    char requested_user[RB2_AUTH_STR_LEN];
    char resolved_user[RB2_AUTH_STR_LEN];
    char rhost[RB2_AUTH_STR_LEN];
    char ruser[RB2_AUTH_STR_LEN];
    char tty[RB2_AUTH_STR_LEN];
};

struct rb2_auth_start_pending {
    rb2_u64 pamh_pp;
    char service[RB2_AUTH_STR_LEN];
    char requested_user[RB2_AUTH_STR_LEN];
};

struct rb2_auth_set_item_pending {
    rb2_u64 pamh;
    rb2_s32 item_type;
    rb2_u64 item_ptr;
};

struct rb2_auth_get_user_pending {
    rb2_u64 pamh;
    rb2_u64 user_pp;
};

struct rb2_auth_call_pending {
    rb2_u64 pamh;
};

#define RB2_PAM_SERVICE 1
#define RB2_PAM_USER 2
#define RB2_PAM_TTY 3
#define RB2_PAM_RHOST 4
#define RB2_PAM_RUSER 8

#define RB2_PAM_SUCCESS 0

#endif
