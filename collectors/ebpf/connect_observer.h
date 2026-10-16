#ifndef AGENTDLP_CONNECT_OBSERVER_H
#define AGENTDLP_CONNECT_OBSERVER_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define CONNECT_COMM_LEN 16

enum redirect_mode {
    REDIRECT_MODE_OBSERVE = 0,
    REDIRECT_MODE_WOULD_REDIRECT = 1,
    REDIRECT_MODE_REDIRECT = 2,
};

enum connect_action {
    CONNECT_ACTION_OBSERVED = 0,
    CONNECT_ACTION_WOULD_REDIRECT = 1,
    CONNECT_ACTION_REDIRECTED = 2,
};

enum connect_event_kind {
    CONNECT_EVENT_ATTEMPT = 0,
    CONNECT_EVENT_SYSCALL_RESULT = 1,
    CONNECT_EVENT_TCP_ESTABLISHED = 2,
    CONNECT_EVENT_TCP_CLOSED = 3,
    CONNECT_EVENT_UDP_SENDMSG_ATTEMPT = 4,
    CONNECT_EVENT_UDP_SENDMSG_RESULT = 5,
};

struct redirect_config {
    __u32 mode;
    __u32 target_ipv4;
    __u32 target_port;
    __u32 redirect_ipv4;
    __u32 redirect_port;
};

struct connect_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 socket_cookie;

    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;

    __u32 family;
    __u32 protocol;
    __u32 socket_type;
    __u32 event_kind;

    __u32 source_ipv4;
    __u32 source_ipv6[4];
    __u32 source_port;
    __u32 destination_ipv4;
    __u32 destination_ipv6[4];
    __u32 destination_port;

    __u32 redirected_destination_ipv4;
    __u32 redirected_destination_port;
    __u32 policy_mode;
    __u32 action;
    __u32 rule_matched;

    __s32 connect_return_code;
    __s32 send_return_code;
    __u32 old_tcp_state;
    __u32 new_tcp_state;
    __u64 bytes_received;
    __u64 bytes_acked;

    char comm[CONNECT_COMM_LEN];
};

#endif
