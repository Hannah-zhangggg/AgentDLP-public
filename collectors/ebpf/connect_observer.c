#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "connect_observer.h"

static volatile sig_atomic_t exiting;
static bool json_output;

struct command_line {
    const char *cgroup_path;
    struct redirect_config policy;
};

static const char *mode_name(__u32 mode)
{
    switch (mode) {
    case REDIRECT_MODE_OBSERVE:
        return "observe";
    case REDIRECT_MODE_WOULD_REDIRECT:
        return "would_redirect";
    case REDIRECT_MODE_REDIRECT:
        return "redirect";
    default:
        return "unknown";
    }
}

static const char *action_name(__u32 action)
{
    switch (action) {
    case CONNECT_ACTION_OBSERVED:
        return "observed";
    case CONNECT_ACTION_WOULD_REDIRECT:
        return "would_redirect";
    case CONNECT_ACTION_REDIRECTED:
        return "redirected";
    default:
        return "unknown";
    }
}

static const char *event_kind_name(__u32 event_kind)
{
    switch (event_kind) {
    case CONNECT_EVENT_ATTEMPT:
        return "connect_attempt";
    case CONNECT_EVENT_SYSCALL_RESULT:
        return "connect_syscall_result";
    case CONNECT_EVENT_TCP_ESTABLISHED:
        return "tcp_established";
    case CONNECT_EVENT_TCP_CLOSED:
        return "tcp_closed";
    case CONNECT_EVENT_UDP_SENDMSG_ATTEMPT:
        return "udp_sendmsg_attempt";
    case CONNECT_EVENT_UDP_SENDMSG_RESULT:
        return "udp_sendmsg_result";
    default:
        return "unknown";
    }
}

static bool private_ipv4(__u32 address)
{
    __u32 host = ntohl(address);

    return (host & 0xff000000U) == 0x0a000000U ||
           (host & 0xfff00000U) == 0xac100000U ||
           (host & 0xffff0000U) == 0xc0a80000U;
}

static int parse_port(const char *value, __u32 *network_port)
{
    char *end = NULL;
    long port;

    errno = 0;
    port = strtol(value, &end, 10);
    if (errno || !end || *end != '\0' || port < 1 || port > 65535)
        return -1;
    *network_port = htons((uint16_t)port);
    return 0;
}

static int parse_mode(const char *value, __u32 *mode)
{
    if (strcmp(value, "observe") == 0) {
        *mode = REDIRECT_MODE_OBSERVE;
    } else if (strcmp(value, "would-redirect") == 0) {
        *mode = REDIRECT_MODE_WOULD_REDIRECT;
    } else if (strcmp(value, "redirect") == 0) {
        *mode = REDIRECT_MODE_REDIRECT;
    } else {
        return -1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s [--json] [--mode observe] CGROUP_PATH\n"
        "       %s [--json] --mode would-redirect "
        "--target-ip IPV4 --target-port PORT "
        "--redirect-ip IPV4 --redirect-port PORT CGROUP_PATH\n"
        "       %s [--json] --mode redirect --ack-controlled-redirect "
        "--target-ip IPV4 --target-port PORT "
        "--redirect-ip IPV4 --redirect-port PORT CGROUP_PATH\n",
        program,
        program,
        program);
}

static int parse_command_line(
    int argc,
    char **argv,
    struct command_line *parsed)
{
    static const struct option options[] = {
        {"json", no_argument, NULL, 'j'},
        {"mode", required_argument, NULL, 'm'},
        {"target-ip", required_argument, NULL, 't'},
        {"target-port", required_argument, NULL, 'p'},
        {"redirect-ip", required_argument, NULL, 'r'},
        {"redirect-port", required_argument, NULL, 'q'},
        {"ack-controlled-redirect", no_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    const char *target_ip = NULL;
    const char *target_port = NULL;
    const char *redirect_ip = NULL;
    const char *redirect_port = NULL;
    bool acknowledged = false;
    int option;

    memset(parsed, 0, sizeof(*parsed));
    parsed->policy.mode = REDIRECT_MODE_OBSERVE;

    while ((option = getopt_long(argc, argv, "jm:t:p:r:q:ah", options, NULL)) != -1) {
        switch (option) {
        case 'j':
            json_output = true;
            break;
        case 'm':
            if (parse_mode(optarg, &parsed->policy.mode) != 0) {
                fprintf(stderr, "invalid --mode: %s\n", optarg);
                return -1;
            }
            break;
        case 't':
            target_ip = optarg;
            break;
        case 'p':
            target_port = optarg;
            break;
        case 'r':
            redirect_ip = optarg;
            break;
        case 'q':
            redirect_port = optarg;
            break;
        case 'a':
            acknowledged = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            return -1;
        }
    }

    if (optind + 1 != argc)
        return -1;
    parsed->cgroup_path = argv[optind];

    if (parsed->policy.mode == REDIRECT_MODE_OBSERVE) {
        if (target_ip || target_port || redirect_ip || redirect_port || acknowledged) {
            fprintf(stderr, "observe mode does not accept a redirect rule\n");
            return -1;
        }
        return 0;
    }

    if (!target_ip || !target_port || !redirect_ip || !redirect_port) {
        fprintf(stderr, "would-redirect/redirect mode requires one complete rule\n");
        return -1;
    }
    if (inet_pton(AF_INET, target_ip, &parsed->policy.target_ipv4) != 1 ||
        inet_pton(AF_INET, redirect_ip, &parsed->policy.redirect_ipv4) != 1) {
        fprintf(stderr, "target and redirect addresses must be IPv4 literals\n");
        return -1;
    }
    if (!private_ipv4(parsed->policy.target_ipv4) ||
        !private_ipv4(parsed->policy.redirect_ipv4)) {
        fprintf(stderr, "controlled redirect addresses must be RFC1918 IPv4\n");
        return -1;
    }
    if (parse_port(target_port, &parsed->policy.target_port) != 0 ||
        parse_port(redirect_port, &parsed->policy.redirect_port) != 0) {
        fprintf(stderr, "target and redirect ports must be in 1..65535\n");
        return -1;
    }
    if (parsed->policy.target_ipv4 == parsed->policy.redirect_ipv4) {
        fprintf(stderr, "target and redirect IP addresses must differ\n");
        return -1;
    }
    if (parsed->policy.mode == REDIRECT_MODE_REDIRECT && !acknowledged) {
        fprintf(stderr, "redirect mode requires --ack-controlled-redirect\n");
        return -1;
    }
    if (parsed->policy.mode != REDIRECT_MODE_REDIRECT && acknowledged) {
        fprintf(stderr, "--ack-controlled-redirect is valid only in redirect mode\n");
        return -1;
    }
    return 0;
}

static void print_comm_hex(const char *comm)
{
    size_t index;

    putchar('"');
    for (index = 0;
         index < CONNECT_COMM_LEN && comm[index] != '\0';
         index++) {
        printf("%02x", (unsigned int)(unsigned char)comm[index]);
    }
    putchar('"');
}

static void handle_signal(int signum)
{
    (void)signum;
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_size)
{
    const struct connect_event *event = data;
    char address[INET6_ADDRSTRLEN] = "unknown";
    char source_address[INET6_ADDRSTRLEN] = "";
    char redirect_address[INET_ADDRSTRLEN] = "";
    const char *family_name = "unknown";
    const char *transport = "unknown";
    const char *redirect_json = "null";
    uint16_t port;
    uint16_t source_port;
    uint16_t redirect_port;

    (void)ctx;

    if (data_size < sizeof(*event)) {
        fprintf(stderr,
                "short ring-buffer event: received=%zu expected=%zu\n",
                data_size,
                sizeof(*event));
        return 0;
    }

    if (event->family == AF_INET) {
        family_name = "ipv4";
        inet_ntop(AF_INET,
                  &event->destination_ipv4,
                  address,
                  sizeof(address));
        if (event->source_ipv4 != 0) {
            inet_ntop(AF_INET,
                      &event->source_ipv4,
                      source_address,
                      sizeof(source_address));
        }
    } else if (event->family == AF_INET6) {
        family_name = "ipv6";
        inet_ntop(AF_INET6,
                  event->destination_ipv6,
                  address,
                  sizeof(address));
        if (event->source_ipv6[0] != 0 ||
            event->source_ipv6[1] != 0 ||
            event->source_ipv6[2] != 0 ||
            event->source_ipv6[3] != 0) {
            inet_ntop(AF_INET6,
                      event->source_ipv6,
                      source_address,
                      sizeof(source_address));
        }
    }

    if (event->protocol == IPPROTO_TCP ||
        event->socket_type == SOCK_STREAM) {
        transport = "tcp";
    } else if (event->protocol == IPPROTO_UDP ||
               event->socket_type == SOCK_DGRAM) {
        transport = "udp";
    }

    port = ntohs((uint16_t)(event->destination_port & 0xffff));
    source_port = ntohs((uint16_t)(event->source_port & 0xffff));
    redirect_port = ntohs(
        (uint16_t)(event->redirected_destination_port & 0xffff));
    if (event->rule_matched &&
        inet_ntop(
            AF_INET,
            &event->redirected_destination_ipv4,
            redirect_address,
            sizeof(redirect_address))) {
        redirect_json = redirect_address;
    }

    if (json_output) {
        printf(
            "{\"event_kind\":\"%s\","
            "\"timestamp_ns\":%llu,\"cgroup_id\":%llu,"
            "\"socket_cookie\":%llu,\"pid\":%u,\"tid\":%u,"
            "\"uid\":%u,\"gid\":%u,\"family\":%u,"
            "\"protocol\":%u,\"socket_type\":%u,"
            "\"source_ip\":",
            event_kind_name(event->event_kind),
            (unsigned long long)event->timestamp_ns,
            (unsigned long long)event->cgroup_id,
            (unsigned long long)event->socket_cookie,
            event->pid,
            event->tid,
            event->uid,
            event->gid,
            event->family,
            event->protocol,
            event->socket_type);
        if (source_address[0] != '\0') {
            printf("\"%s\",", source_address);
        } else {
            fputs("null,", stdout);
        }
        printf(
            "\"source_port\":%u,"
            "\"destination_ip\":\"%s\","
            "\"destination_port\":%u,",
            source_port,
            address,
            port);
        if (event->rule_matched) {
            printf(
                "\"redirected_destination_ip\":\"%s\",",
                redirect_json);
        } else {
            fputs("\"redirected_destination_ip\":null,", stdout);
        }
        printf(
            "\"redirected_destination_port\":%u,"
            "\"policy_mode\":\"%s\",\"action\":\"%s\","
            "\"rule_matched\":%s,",
            redirect_port,
            mode_name(event->policy_mode),
            action_name(event->action),
            event->rule_matched ? "true" : "false");
        if (event->event_kind == CONNECT_EVENT_SYSCALL_RESULT) {
            printf(
                "\"connect_return_code\":%d,",
                event->connect_return_code);
        } else {
            fputs("\"connect_return_code\":null,", stdout);
        }
        if (event->event_kind == CONNECT_EVENT_UDP_SENDMSG_RESULT) {
            printf(
                "\"send_return_code\":%d,",
                event->send_return_code);
        } else {
            fputs("\"send_return_code\":null,", stdout);
        }
        if (event->event_kind == CONNECT_EVENT_TCP_CLOSED) {
            printf(
                "\"old_tcp_state\":%u,\"new_tcp_state\":%u,"
                "\"bytes_received\":%llu,\"bytes_acked\":%llu,",
                event->old_tcp_state,
                event->new_tcp_state,
                (unsigned long long)event->bytes_received,
                (unsigned long long)event->bytes_acked);
        } else {
            fputs(
                "\"old_tcp_state\":null,\"new_tcp_state\":null,"
                "\"bytes_received\":null,\"bytes_acked\":null,",
                stdout);
        }
        fputs("\"comm_hex\":", stdout);
        print_comm_hex(event->comm);
        fputs("}\n", stdout);
    } else {
        printf(
            "event_kind=%s timestamp_ns=%llu pid=%u tid=%u uid=%u gid=%u "
            "comm=%.*s cgroup_id=%llu family=%s transport=%s "
            "protocol=%u socket_type=%u source=%s:%u destination=%s:%u "
            "policy_mode=%s action=%s rule_matched=%s "
            "redirect_destination=%s:%u socket_cookie=%llu "
            "connect_return_code=%d send_return_code=%d "
            "bytes_received=%llu bytes_acked=%llu\n",
            event_kind_name(event->event_kind),
            (unsigned long long)event->timestamp_ns,
            event->pid,
            event->tid,
            event->uid,
            event->gid,
            CONNECT_COMM_LEN,
            event->comm,
            (unsigned long long)event->cgroup_id,
            family_name,
            transport,
            event->protocol,
            event->socket_type,
            source_address[0] ? source_address : "unavailable",
            source_port,
            address,
            port,
            mode_name(event->policy_mode),
            action_name(event->action),
            event->rule_matched ? "yes" : "no",
            event->rule_matched ? redirect_address : "none",
            redirect_port,
            (unsigned long long)event->socket_cookie,
            event->connect_return_code,
            event->send_return_code,
            (unsigned long long)event->bytes_received,
            (unsigned long long)event->bytes_acked);
    }

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    struct command_line command_line;
    struct bpf_object *object = NULL;
    struct bpf_program *program4;
    struct bpf_program *program6;
    struct bpf_program *program_result;
    struct bpf_program *program_sendmsg4;
    struct bpf_program *program_sendmsg6;
    struct bpf_program *program_sendmsg_result;
    struct bpf_program *program_sendto_result;
    struct bpf_program *program_sendmmsg_result;
    struct bpf_program *program_connected_udp_sendmsg;
    struct bpf_program *program_sockops;
    struct bpf_link *link4 = NULL;
    struct bpf_link *link6 = NULL;
    struct bpf_link *link_result = NULL;
    struct bpf_link *link_sendmsg4 = NULL;
    struct bpf_link *link_sendmsg6 = NULL;
    struct bpf_link *link_sendmsg_result = NULL;
    struct bpf_link *link_sendto_result = NULL;
    struct bpf_link *link_sendmmsg_result = NULL;
    struct bpf_link *link_connected_udp_sendmsg = NULL;
    struct bpf_link *link_sockops = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct rlimit memlock = {RLIM_INFINITY, RLIM_INFINITY};
    char object_path_buffer[PATH_MAX];
    const char *object_path;

    int cgroup_fd = -1;
    int events_fd;
    int policy_fd;
    int target_cgroup_fd;
    int result = EXIT_FAILURE;
    int err;
    long libbpf_err;
    struct stat cgroup_stat;

    if (parse_command_line(argc, argv, &command_line) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &memlock) != 0) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    cgroup_fd = open(
        command_line.cgroup_path,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        perror("open cgroup");
        goto cleanup;
    }

    object_path = getenv("AGENTDLP_EBPF_OBJECT");
    if (!object_path || object_path[0] == '\0') {
        ssize_t executable_length;
        char *last_slash;
        const char object_name[] = "connect_observer.bpf.o";

        executable_length = readlink(
            "/proc/self/exe",
            object_path_buffer,
            sizeof(object_path_buffer) - 1);
        if (executable_length < 0) {
            perror("readlink /proc/self/exe");
            goto cleanup;
        }
        object_path_buffer[executable_length] = '\0';
        last_slash = strrchr(object_path_buffer, '/');
        if (!last_slash ||
            (size_t)(last_slash - object_path_buffer + 1) +
                sizeof(object_name) > sizeof(object_path_buffer)) {
            fprintf(stderr, "failed to resolve BPF object path\n");
            goto cleanup;
        }
        memcpy(last_slash + 1, object_name, sizeof(object_name));
        object_path = object_path_buffer;
    }

    object = bpf_object__open_file(object_path, NULL);
    libbpf_err = libbpf_get_error(object);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to open BPF object: error=%ld\n",
                libbpf_err);
        object = NULL;
        goto cleanup;
    }

    err = bpf_object__load(object);
    if (err) {
        fprintf(stderr,
                "failed to load BPF object: error=%d\n",
                err);
        goto cleanup;
    }

    policy_fd = bpf_object__find_map_fd_by_name(
        object,
        "redirect_policy");
    if (policy_fd < 0) {
        fprintf(stderr, "failed to find redirect policy map\n");
        goto cleanup;
    }

    target_cgroup_fd = bpf_object__find_map_fd_by_name(
        object,
        "target_cgroup_id");
    if (target_cgroup_fd < 0 || fstat(cgroup_fd, &cgroup_stat) != 0) {
        perror("resolve target cgroup id");
        goto cleanup;
    }
    {
        __u32 key = 0;
        __u64 cgroup_id = (__u64)cgroup_stat.st_ino;

        if (bpf_map_update_elem(
                target_cgroup_fd,
                &key,
                &cgroup_id,
                BPF_ANY) != 0) {
            perror("bpf_map_update_elem target_cgroup_id");
            goto cleanup;
        }
    }
    {
        __u32 key = 0;

        if (bpf_map_update_elem(
                policy_fd,
                &key,
                &command_line.policy,
                BPF_ANY) != 0) {
            perror("bpf_map_update_elem redirect_policy");
            goto cleanup;
        }
    }

    program4 = bpf_object__find_program_by_name(
        object,
        "observe_connect4");
    program6 = bpf_object__find_program_by_name(
        object,
        "observe_connect6");
    program_result = bpf_object__find_program_by_name(
        object,
        "observe_connect_result");
    program_sendmsg4 = bpf_object__find_program_by_name(
        object,
        "observe_sendmsg4");
    program_sendmsg6 = bpf_object__find_program_by_name(
        object,
        "observe_sendmsg6");
    program_sendmsg_result = bpf_object__find_program_by_name(
        object,
        "observe_sendmsg_result");
    program_sendto_result = bpf_object__find_program_by_name(
        object,
        "observe_sendto_result");
    program_sendmmsg_result = bpf_object__find_program_by_name(
        object,
        "observe_sendmmsg_result");
    program_connected_udp_sendmsg = bpf_object__find_program_by_name(
        object,
        "observe_connected_udp_sendmsg");
    program_sockops = bpf_object__find_program_by_name(
        object,
        "observe_tcp_lifecycle");

    if (!program4 || !program6 || !program_result ||
        !program_sendmsg4 || !program_sendmsg6 ||
        !program_sendmsg_result || !program_sendto_result ||
        !program_sendmmsg_result ||
        !program_connected_udp_sendmsg ||
        !program_sockops) {
        fprintf(
            stderr,
            "failed to find connect/sendmsg/result/sockops programs\n");
        goto cleanup;
    }

    link4 = bpf_program__attach_cgroup(program4, cgroup_fd);
    libbpf_err = libbpf_get_error(link4);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach connect4: error=%ld\n",
                libbpf_err);
        link4 = NULL;
        goto cleanup;
    }

    link_connected_udp_sendmsg = bpf_program__attach_kprobe(
        program_connected_udp_sendmsg,
        false,
        "udp_sendmsg");
    libbpf_err = libbpf_get_error(link_connected_udp_sendmsg);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach udp_sendmsg kprobe: error=%ld\n",
                libbpf_err);
        link_connected_udp_sendmsg = NULL;
        goto cleanup;
    }

    link_sendmmsg_result = bpf_program__attach_tracepoint(
        program_sendmmsg_result,
        "syscalls",
        "sys_exit_sendmmsg");
    libbpf_err = libbpf_get_error(link_sendmmsg_result);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sys_exit_sendmmsg: error=%ld\n",
                libbpf_err);
        link_sendmmsg_result = NULL;
        goto cleanup;
    }

    link_sockops = bpf_program__attach_cgroup(program_sockops, cgroup_fd);
    libbpf_err = libbpf_get_error(link_sockops);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sockops: error=%ld\n",
                libbpf_err);
        link_sockops = NULL;
        goto cleanup;
    }

    link_result = bpf_program__attach_tracepoint(
        program_result,
        "syscalls",
        "sys_exit_connect");
    libbpf_err = libbpf_get_error(link_result);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sys_exit_connect: error=%ld\n",
                libbpf_err);
        link_result = NULL;
        goto cleanup;
    }

    link6 = bpf_program__attach_cgroup(program6, cgroup_fd);
    libbpf_err = libbpf_get_error(link6);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach connect6: error=%ld\n",
                libbpf_err);
        link6 = NULL;
        goto cleanup;
    }

    link_sendmsg4 = bpf_program__attach_cgroup(program_sendmsg4, cgroup_fd);
    libbpf_err = libbpf_get_error(link_sendmsg4);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sendmsg4: error=%ld\n",
                libbpf_err);
        link_sendmsg4 = NULL;
        goto cleanup;
    }

    link_sendmsg6 = bpf_program__attach_cgroup(program_sendmsg6, cgroup_fd);
    libbpf_err = libbpf_get_error(link_sendmsg6);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sendmsg6: error=%ld\n",
                libbpf_err);
        link_sendmsg6 = NULL;
        goto cleanup;
    }

    link_sendmsg_result = bpf_program__attach_tracepoint(
        program_sendmsg_result,
        "syscalls",
        "sys_exit_sendmsg");
    libbpf_err = libbpf_get_error(link_sendmsg_result);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sys_exit_sendmsg: error=%ld\n",
                libbpf_err);
        link_sendmsg_result = NULL;
        goto cleanup;
    }

    link_sendto_result = bpf_program__attach_tracepoint(
        program_sendto_result,
        "syscalls",
        "sys_exit_sendto");
    libbpf_err = libbpf_get_error(link_sendto_result);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to attach sys_exit_sendto: error=%ld\n",
                libbpf_err);
        link_sendto_result = NULL;
        goto cleanup;
    }

    events_fd = bpf_object__find_map_fd_by_name(object, "events");
    if (events_fd < 0) {
        fprintf(stderr, "failed to find events ring buffer\n");
        goto cleanup;
    }

    ring_buffer = ring_buffer__new(
        events_fd,
        handle_event,
        NULL,
        NULL);
    libbpf_err = libbpf_get_error(ring_buffer);
    if (libbpf_err) {
        fprintf(stderr,
                "failed to create ring buffer: error=%ld\n",
                libbpf_err);
        ring_buffer = NULL;
        goto cleanup;
    }

    fprintf(stderr,
            "observing connect4/connect6/sendmsg4/sendmsg6 on cgroup: %s\n",
            command_line.cgroup_path);

    while (!exiting) {
        err = ring_buffer__poll(ring_buffer, 250);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr,
                    "ring-buffer polling failed: error=%d\n",
                    err);
            goto cleanup;
        }
    }

    result = EXIT_SUCCESS;

cleanup:
    ring_buffer__free(ring_buffer);
    bpf_link__destroy(link_connected_udp_sendmsg);
    bpf_link__destroy(link_sendmmsg_result);
    bpf_link__destroy(link_sendto_result);
    bpf_link__destroy(link_sendmsg_result);
    bpf_link__destroy(link_sendmsg6);
    bpf_link__destroy(link_sendmsg4);
    bpf_link__destroy(link_result);
    bpf_link__destroy(link_sockops);
    bpf_link__destroy(link6);
    bpf_link__destroy(link4);
    bpf_object__close(object);

    if (cgroup_fd >= 0)
        close(cgroup_fd);

    return result;
}
