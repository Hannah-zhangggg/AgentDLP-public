#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "connect_observer.h"

#define AF_INET  2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define EINPROGRESS 115
#define EALREADY 114
#define TCP_CLOSE 7

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct redirect_config);
} redirect_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct connect_event);
} pending_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct connect_event);
} pending_udp_sends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct connect_event);
} socket_contexts SEC(".maps");

static __always_inline void submit_event(const struct connect_event *source)
{
    struct connect_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    __builtin_memcpy(event, source, sizeof(*event));
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int emit_connect(
    struct bpf_sock_addr *ctx,
    __u32 family)
{
    const struct redirect_config *config;
    struct connect_event event = {};
    __u32 config_key = 0;
    __u32 rule_matched = 0;
    __u64 pid_tgid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.socket_cookie = bpf_get_socket_cookie(ctx);

    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.uid = (__u32)uid_gid;
    event.gid = uid_gid >> 32;

    event.family = family;
    event.protocol = ctx->protocol;
    event.socket_type = ctx->type;
    event.event_kind = CONNECT_EVENT_ATTEMPT;
    event.destination_port = ctx->user_port;
    event.action = CONNECT_ACTION_OBSERVED;

    bpf_get_current_comm(event.comm, sizeof(event.comm));

    if (family == AF_INET) {
        event.destination_ipv4 = ctx->user_ip4;
    } else {
        event.destination_ipv6[0] = ctx->user_ip6[0];
        event.destination_ipv6[1] = ctx->user_ip6[1];
        event.destination_ipv6[2] = ctx->user_ip6[2];
        event.destination_ipv6[3] = ctx->user_ip6[3];
    }

    config = bpf_map_lookup_elem(&redirect_policy, &config_key);
    if (config) {
        event.policy_mode = config->mode;
        rule_matched = (
            family == AF_INET &&
            (ctx->protocol == IPPROTO_TCP || ctx->type == SOCK_STREAM) &&
            ctx->user_ip4 == config->target_ipv4 &&
            ctx->user_port == config->target_port &&
            config->mode != REDIRECT_MODE_OBSERVE
        );
    }

    if (rule_matched) {
        event.rule_matched = 1;
        event.redirected_destination_ipv4 = config->redirect_ipv4;
        event.redirected_destination_port = config->redirect_port;

        if (config->mode == REDIRECT_MODE_WOULD_REDIRECT) {
            event.action = CONNECT_ACTION_WOULD_REDIRECT;
        } else if (config->mode == REDIRECT_MODE_REDIRECT) {
            ctx->user_ip4 = config->redirect_ipv4;
            ctx->user_port = config->redirect_port;
            event.action = CONNECT_ACTION_REDIRECTED;
        }
    }

    bpf_map_update_elem(
        &pending_connects,
        &event.tid,
        &event,
        BPF_ANY);
    if (event.socket_cookie != 0) {
        bpf_map_update_elem(
            &socket_contexts,
            &event.socket_cookie,
            &event,
            BPF_ANY);
    }
    submit_event(&event);
    return 1;
}

SEC("cgroup/connect4")
int observe_connect4(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET);
}

SEC("cgroup/connect6")
int observe_connect6(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET6);
}

static __always_inline int emit_udp_sendmsg(
    struct bpf_sock_addr *ctx,
    __u32 family)
{
    struct connect_event event = {};
    __u64 pid_tgid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.socket_cookie = bpf_get_socket_cookie(ctx);
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.uid = (__u32)uid_gid;
    event.gid = uid_gid >> 32;
    event.family = family;
    event.protocol = ctx->protocol ? ctx->protocol : IPPROTO_UDP;
    event.socket_type = ctx->type ? ctx->type : SOCK_DGRAM;
    event.event_kind = CONNECT_EVENT_UDP_SENDMSG_ATTEMPT;
    event.destination_port = ctx->user_port;
    event.action = CONNECT_ACTION_OBSERVED;
    bpf_get_current_comm(event.comm, sizeof(event.comm));

    if (family == AF_INET) {
        event.destination_ipv4 = ctx->user_ip4;
        event.source_ipv4 = ctx->msg_src_ip4;
    } else {
        event.destination_ipv6[0] = ctx->user_ip6[0];
        event.destination_ipv6[1] = ctx->user_ip6[1];
        event.destination_ipv6[2] = ctx->user_ip6[2];
        event.destination_ipv6[3] = ctx->user_ip6[3];
        event.source_ipv6[0] = ctx->msg_src_ip6[0];
        event.source_ipv6[1] = ctx->msg_src_ip6[1];
        event.source_ipv6[2] = ctx->msg_src_ip6[2];
        event.source_ipv6[3] = ctx->msg_src_ip6[3];
    }

    bpf_map_update_elem(
        &pending_udp_sends,
        &event.tid,
        &event,
        BPF_ANY);
    submit_event(&event);
    return 1;
}

SEC("cgroup/sendmsg4")
int observe_sendmsg4(struct bpf_sock_addr *ctx)
{
    return emit_udp_sendmsg(ctx, AF_INET);
}

SEC("cgroup/sendmsg6")
int observe_sendmsg6(struct bpf_sock_addr *ctx)
{
    return emit_udp_sendmsg(ctx, AF_INET6);
}

/* cgroup/sendmsg is not invoked for a connected UDP socket with msg_name=NULL.
 * Observe that path at udp_sendmsg while keeping payloads opaque. */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(
    observe_connected_udp_sendmsg,
    struct sock *sk,
    struct msghdr *message)
{
    struct connect_event event = {};
    const __u64 *target_cgroup;
    void *message_name;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u32 family;
    __u32 key = 0;

    target_cgroup = bpf_map_lookup_elem(&target_cgroup_id, &key);
    if (!target_cgroup || bpf_get_current_cgroup_id() != *target_cgroup)
        return 0;

    message_name = BPF_CORE_READ(message, msg_name);
    if (message_name)
        return 0;
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = *target_cgroup;
    /* This helper is unavailable to kprobe programs. Zero is an explicit
     * correlation gap; the exit event is paired by TID and remains metadata. */
    event.socket_cookie = 0;
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.uid = (__u32)uid_gid;
    event.gid = uid_gid >> 32;
    event.family = AF_INET;
    event.protocol = IPPROTO_UDP;
    event.socket_type = SOCK_DGRAM;
    event.event_kind = CONNECT_EVENT_UDP_SENDMSG_ATTEMPT;
    event.source_ipv4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.source_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
    event.destination_ipv4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.destination_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.action = CONNECT_ACTION_OBSERVED;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(
        &pending_udp_sends,
        &event.tid,
        &event,
        BPF_ANY);
    submit_event(&event);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int observe_connect_result(struct trace_event_raw_sys_exit *ctx)
{
    const struct connect_event *pending;
    struct connect_event event = {};
    __u64 pid_tgid;
    __u32 tid;
    long return_code;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32)pid_tgid;
    pending = bpf_map_lookup_elem(&pending_connects, &tid);
    if (!pending)
        return 0;

    __builtin_memcpy(&event, pending, sizeof(event));
    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_kind = CONNECT_EVENT_SYSCALL_RESULT;
    return_code = ctx->ret;
    event.connect_return_code = (__s32)return_code;
    submit_event(&event);

    bpf_map_delete_elem(&pending_connects, &tid);
    if (
        return_code < 0 &&
        return_code != -EINPROGRESS &&
        return_code != -EALREADY &&
        event.socket_cookie != 0
    ) {
        bpf_map_delete_elem(&socket_contexts, &event.socket_cookie);
    }
    return 0;
}

static __always_inline int emit_udp_send_result(
    struct trace_event_raw_sys_exit *ctx)
{
    const struct connect_event *pending;
    struct connect_event event = {};
    __u64 pid_tgid;
    __u32 tid;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32)pid_tgid;
    pending = bpf_map_lookup_elem(&pending_udp_sends, &tid);
    if (!pending)
        return 0;

    __builtin_memcpy(&event, pending, sizeof(event));
    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_kind = CONNECT_EVENT_UDP_SENDMSG_RESULT;
    event.send_return_code = (__s32)ctx->ret;
    submit_event(&event);
    bpf_map_delete_elem(&pending_udp_sends, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int observe_sendmsg_result(struct trace_event_raw_sys_exit *ctx)
{
    return emit_udp_send_result(ctx);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int observe_sendto_result(struct trace_event_raw_sys_exit *ctx)
{
    return emit_udp_send_result(ctx);
}

/* cgroup/sendmsg{4,6} also gates datagram sends issued by sendmmsg(2). */
SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int observe_sendmmsg_result(struct trace_event_raw_sys_exit *ctx)
{
    return emit_udp_send_result(ctx);
}

static __attribute__((noinline)) void populate_sockops_source4(
    struct connect_event *event,
    const struct bpf_sock_ops *ctx)
{
    event->source_port = bpf_htons((__u16)ctx->local_port);
    event->source_ipv4 = ctx->local_ip4;
}

static __attribute__((noinline)) void populate_sockops_source6(
    struct connect_event *event,
    const struct bpf_sock_ops *ctx)
{
    event->source_port = bpf_htons((__u16)ctx->local_port);
    event->source_ipv6[0] = ctx->local_ip6[0];
    event->source_ipv6[1] = ctx->local_ip6[1];
    event->source_ipv6[2] = ctx->local_ip6[2];
    event->source_ipv6[3] = ctx->local_ip6[3];
}

static __always_inline void populate_sockops_source(
    struct connect_event *event,
    const struct bpf_sock_ops *ctx)
{
    if (ctx->family == AF_INET)
        populate_sockops_source4(event, ctx);
    else if (ctx->family == AF_INET6)
        populate_sockops_source6(event, ctx);
}

SEC("sockops")
int observe_tcp_lifecycle(struct bpf_sock_ops *ctx)
{
    const struct connect_event *connection;
    struct connect_event event = {};
    __u64 socket_cookie;

    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 1;

    socket_cookie = bpf_get_socket_cookie(ctx);
    if (socket_cookie == 0)
        return 1;
    connection = bpf_map_lookup_elem(&socket_contexts, &socket_cookie);
    if (!connection)
        return 1;

    if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        __builtin_memcpy(&event, connection, sizeof(event));
        event.timestamp_ns = bpf_ktime_get_ns();
        event.event_kind = CONNECT_EVENT_TCP_ESTABLISHED;
        populate_sockops_source(&event, ctx);
        bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_STATE_CB_FLAG);
        bpf_map_update_elem(
            &socket_contexts,
            &socket_cookie,
            &event,
            BPF_ANY);
        submit_event(&event);
        return 1;
    }

    if (
        ctx->op == BPF_SOCK_OPS_STATE_CB &&
        ctx->args[1] == TCP_CLOSE
    ) {
        __builtin_memcpy(&event, connection, sizeof(event));
        event.timestamp_ns = bpf_ktime_get_ns();
        event.event_kind = CONNECT_EVENT_TCP_CLOSED;
        event.old_tcp_state = ctx->args[0];
        event.new_tcp_state = ctx->args[1];
        event.bytes_received = ctx->bytes_received;
        event.bytes_acked = ctx->bytes_acked;
        populate_sockops_source(&event, ctx);
        submit_event(&event);
        bpf_map_delete_elem(&socket_contexts, &socket_cookie);
    }

    return 1;
}
