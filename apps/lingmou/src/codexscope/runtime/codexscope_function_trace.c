#define _GNU_SOURCE 1

#include "codexscope_function_trace.h"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

#define CXS_SCHEMA "codexscope.function_trace.v1"
#define CXS_STACK_LIMIT 1024U
#define CXS_JSON_LIMIT 8192U
#define CXS_SYMBOL_LIMIT 512U

#define CXS_NOINSTRUMENT CODEXSCOPE_NOINSTRUMENT

struct cxs_frame {
    void *function;
    unsigned long long activation;
    unsigned long long parent;
    unsigned int depth;
};

struct cxs_module {
    char relative_path[PATH_MAX];
    char symbol[CXS_SYMBOL_LIMIT];
    uintptr_t address;
    uintptr_t base;
    uintptr_t offset;
    dev_t device;
    ino_t inode;
    off_t size;
    long long mtime_ns;
};

static pthread_once_t cxs_once = PTHREAD_ONCE_INIT;
static int cxs_socket_fd = -1;
static int cxs_enabled = 0;
static char cxs_root[PATH_MAX];
static char cxs_instance[128];
static unsigned long long cxs_max_calls = 100000ULL;
static _Atomic unsigned long long cxs_calls = 0;
static _Atomic unsigned long long cxs_sequence = 0;
static _Atomic unsigned long long cxs_records = 0;
static _Atomic unsigned long long cxs_dropped = 0;
static _Atomic int cxs_limit_sent = 0;
static _Atomic int cxs_owner_pid = 0;
static _Thread_local struct cxs_frame cxs_stack[CXS_STACK_LIMIT];
static _Thread_local unsigned int cxs_depth = 0;
static _Thread_local unsigned int cxs_suppressed_depth = 0;
static _Thread_local pid_t cxs_thread_pid = 0;
static _Thread_local volatile sig_atomic_t cxs_in_callback = 0;

static CXS_NOINSTRUMENT unsigned long long cxs_clock_ns(clockid_t clock_id) {
    struct timespec value;
    if (clock_gettime(clock_id, &value) != 0) {
        return 0ULL;
    }
    return (unsigned long long)value.tv_sec * 1000000000ULL +
           (unsigned long long)value.tv_nsec;
}

static CXS_NOINSTRUMENT long cxs_thread_id(void) {
#if defined(__linux__) && defined(SYS_gettid)
    return (long)syscall(SYS_gettid);
#else
    return (long)(uintptr_t)pthread_self();
#endif
}

static CXS_NOINSTRUMENT int cxs_language_enabled(const char *value) {
    const char *cursor = value;
    while (cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        if (length == 1U && cursor[0] == 'c') {
            return 1;
        }
        cursor = end == NULL ? NULL : end + 1;
    }
    return 0;
}

static CXS_NOINSTRUMENT size_t cxs_json_escape(
    const char *input, char *output, size_t capacity
) {
    size_t used = 0U;
    const unsigned char *cursor = (const unsigned char *)input;
    if (capacity == 0U) {
        return 0U;
    }
    while (cursor != NULL && *cursor != '\0' && used + 2U < capacity) {
        unsigned char value = *cursor++;
        if (value == '"' || value == '\\') {
            output[used++] = '\\';
            output[used++] = (char)value;
        } else if (value == '\n' || value == '\r' || value == '\t') {
            output[used++] = '\\';
            output[used++] = value == '\n' ? 'n' : value == '\r' ? 'r' : 't';
        } else if (value >= 0x20U) {
            output[used++] = (char)value;
        }
    }
    output[used] = '\0';
    return used;
}

static CXS_NOINSTRUMENT void cxs_send(const char *payload, size_t length) {
    ssize_t sent;
    int flags = MSG_DONTWAIT;
#if defined(MSG_NOSIGNAL)
    flags |= MSG_NOSIGNAL;
#endif
    if (!cxs_enabled || cxs_socket_fd < 0 || length == 0U) {
        return;
    }
    sent = send(cxs_socket_fd, payload, length, flags);
    if (sent != (ssize_t)length) {
        atomic_fetch_add_explicit(&cxs_dropped, 1ULL, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&cxs_records, 1ULL, memory_order_relaxed);
    }
}

static CXS_NOINSTRUMENT void cxs_set_instance(pid_t pid) {
    unsigned long long marker = cxs_clock_ns(CLOCK_MONOTONIC);
    (void)snprintf(
        cxs_instance, sizeof(cxs_instance), "%ld:%llu", (long)pid, marker
    );
}

static CXS_NOINSTRUMENT void cxs_send_control(const char *kind) {
    char payload[1024];
    unsigned long long process_seq =
        atomic_fetch_add_explicit(&cxs_sequence, 1ULL, memory_order_relaxed) + 1ULL;
    int length = snprintf(
        payload,
        sizeof(payload),
        "{\"schema\":\"%s\",\"kind\":\"%s\","
        "\"backend\":\"c_finstrument\",\"language\":\"c\","
        "\"pid\":%ld,\"ppid\":%ld,\"process_instance_id\":\"%s\","
        "\"runtime_thread_id\":%ld,\"process_seq\":%llu,"
        "\"monotonic_ns\":%llu,\"wall_time_ns\":%llu,"
        "\"calls_started\":%llu,\"records_dropped\":%llu}",
        CXS_SCHEMA,
        kind,
        (long)getpid(),
        (long)getppid(),
        cxs_instance,
        cxs_thread_id(),
        process_seq,
        cxs_clock_ns(CLOCK_MONOTONIC),
        cxs_clock_ns(CLOCK_REALTIME),
        atomic_load_explicit(&cxs_calls, memory_order_relaxed),
        atomic_load_explicit(&cxs_dropped, memory_order_relaxed)
    );
    if (length > 0 && (size_t)length < sizeof(payload)) {
        cxs_send(payload, (size_t)length);
    }
}

static CXS_NOINSTRUMENT void cxs_shutdown(void) {
    if (!cxs_enabled) {
        return;
    }
    cxs_send_control("process_end");
    if (cxs_socket_fd >= 0) {
        close(cxs_socket_fd);
        cxs_socket_fd = -1;
    }
    cxs_enabled = 0;
}

static CXS_NOINSTRUMENT void cxs_initialize(void) {
    const char *languages = getenv("CODEXSCOPE_FUNCTION_TRACE");
    const char *socket_path = getenv("CODEXSCOPE_FUNCTION_SOCKET");
    const char *root = getenv("CODEXSCOPE_FUNCTION_ROOT");
    const char *maximum = getenv("CODEXSCOPE_FUNCTION_MAX_CALLS");
    struct sockaddr_un address;
    char resolved_root[PATH_MAX];
    unsigned long long parsed;
    char *end = NULL;
    pid_t pid = getpid();

    if (!cxs_language_enabled(languages) || socket_path == NULL || root == NULL) {
        return;
    }
    if (realpath(root, resolved_root) == NULL) {
        return;
    }
    if (strlen(resolved_root) >= sizeof(cxs_root)) {
        return;
    }
    (void)strcpy(cxs_root, resolved_root);
    while (strlen(cxs_root) > 1U && cxs_root[strlen(cxs_root) - 1U] == '/') {
        cxs_root[strlen(cxs_root) - 1U] = '\0';
    }
    if (maximum != NULL) {
        errno = 0;
        parsed = strtoull(maximum, &end, 10);
        if (errno == 0 && end != maximum && *end == '\0' && parsed > 0ULL) {
            cxs_max_calls = parsed;
        }
    }
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        return;
    }
    cxs_socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (cxs_socket_fd < 0) {
        return;
    }
    (void)memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)strcpy(address.sun_path, socket_path);
    if (connect(cxs_socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(cxs_socket_fd);
        cxs_socket_fd = -1;
        return;
    }
    cxs_set_instance(pid);
    atomic_store_explicit(&cxs_owner_pid, (int)pid, memory_order_relaxed);
    cxs_thread_pid = pid;
    cxs_enabled = 1;
    (void)atexit(cxs_shutdown);
    cxs_send_control("process_start");
}

static CXS_NOINSTRUMENT void cxs_refresh_after_fork(void) {
    pid_t pid = getpid();
    int owner = atomic_load_explicit(&cxs_owner_pid, memory_order_relaxed);
    if (owner == (int)pid) {
        if (cxs_thread_pid != pid) {
            cxs_thread_pid = pid;
            cxs_depth = 0U;
            cxs_suppressed_depth = 0U;
        }
        return;
    }
    if (atomic_compare_exchange_strong_explicit(
            &cxs_owner_pid,
            &owner,
            (int)pid,
            memory_order_relaxed,
            memory_order_relaxed
        )) {
        atomic_store_explicit(&cxs_calls, 0ULL, memory_order_relaxed);
        atomic_store_explicit(&cxs_sequence, 0ULL, memory_order_relaxed);
        atomic_store_explicit(&cxs_records, 0ULL, memory_order_relaxed);
        atomic_store_explicit(&cxs_dropped, 0ULL, memory_order_relaxed);
        atomic_store_explicit(&cxs_limit_sent, 0, memory_order_relaxed);
        cxs_set_instance(pid);
        cxs_send_control("process_start");
    }
    cxs_thread_pid = pid;
    cxs_depth = 0U;
    cxs_suppressed_depth = 0U;
}

static CXS_NOINSTRUMENT int cxs_under_root(
    const char *absolute, char *relative, size_t capacity
) {
    size_t root_length = strlen(cxs_root);
    const char *suffix;
    if (strncmp(absolute, cxs_root, root_length) != 0) {
        return 0;
    }
    if (root_length > 1U && absolute[root_length] != '/' && absolute[root_length] != '\0') {
        return 0;
    }
    suffix = absolute + root_length;
    if (*suffix == '/') {
        ++suffix;
    }
    if (*suffix == '\0' || strlen(suffix) >= capacity) {
        return 0;
    }
    (void)strcpy(relative, suffix);
    return 1;
}

static CXS_NOINSTRUMENT int cxs_module_for(
    void *function, struct cxs_module *module
) {
    Dl_info info;
    char absolute[PATH_MAX];
    char candidate[PATH_MAX];
    struct stat metadata;
    (void)memset(module, 0, sizeof(*module));
    if (dladdr(function, &info) == 0 || info.dli_fname == NULL) {
        return 0;
    }
    if (realpath(info.dli_fname, absolute) == NULL) {
        if (info.dli_fname[0] == '/') {
            if (strlen(info.dli_fname) >= sizeof(absolute)) {
                return 0;
            }
            (void)strcpy(absolute, info.dli_fname);
        } else {
            if (getcwd(candidate, sizeof(candidate)) == NULL ||
                strlen(candidate) + strlen(info.dli_fname) + 2U >= sizeof(candidate)) {
                return 0;
            }
            (void)strcat(candidate, "/");
            (void)strcat(candidate, info.dli_fname);
            if (realpath(candidate, absolute) == NULL) {
                return 0;
            }
        }
    }
    if (!cxs_under_root(absolute, module->relative_path, sizeof(module->relative_path))) {
        return 0;
    }
    module->address = (uintptr_t)function;
    module->base = (uintptr_t)info.dli_fbase;
    module->offset = module->address - module->base;
    if (info.dli_sname != NULL) {
        (void)snprintf(module->symbol, sizeof(module->symbol), "%s", info.dli_sname);
    }
    if (stat(absolute, &metadata) == 0) {
        module->device = metadata.st_dev;
        module->inode = metadata.st_ino;
        module->size = metadata.st_size;
#if defined(__APPLE__)
        module->mtime_ns = (long long)metadata.st_mtimespec.tv_sec * 1000000000LL +
                           (long long)metadata.st_mtimespec.tv_nsec;
#else
        module->mtime_ns = (long long)metadata.st_mtim.tv_sec * 1000000000LL +
                           (long long)metadata.st_mtim.tv_nsec;
#endif
    }
    return 1;
}

static CXS_NOINSTRUMENT void cxs_send_frame(
    const char *kind,
    const struct cxs_module *module,
    const struct cxs_frame *frame,
    void *call_site,
    unsigned long long monotonic_ns,
    unsigned long long wall_time_ns
) {
    char payload[CXS_JSON_LIMIT];
    char escaped_path[PATH_MAX * 2U];
    char escaped_symbol[CXS_SYMBOL_LIMIT * 2U];
    char parent[192];
    unsigned long long process_seq =
        atomic_fetch_add_explicit(&cxs_sequence, 1ULL, memory_order_relaxed) + 1ULL;
    int length;
    (void)cxs_json_escape(module->relative_path, escaped_path, sizeof(escaped_path));
    (void)cxs_json_escape(module->symbol, escaped_symbol, sizeof(escaped_symbol));
    if (frame->parent == 0ULL) {
        (void)strcpy(parent, "null");
    } else {
        (void)snprintf(
            parent,
            sizeof(parent),
            "\"%s:t%ld:a%llu\"",
            cxs_instance,
            cxs_thread_id(),
            frame->parent
        );
    }
    length = snprintf(
        payload,
        sizeof(payload),
        "{\"schema\":\"%s\",\"kind\":\"%s\","
        "\"backend\":\"c_finstrument\",\"language\":\"c\","
        "\"pid\":%ld,\"ppid\":%ld,\"process_instance_id\":\"%s\","
        "\"runtime_thread_id\":%ld,\"process_seq\":%llu,"
        "\"monotonic_ns\":%llu,\"wall_time_ns\":%llu,"
        "\"activation_id\":\"%s:t%ld:a%llu\","
        "\"caller_activation_id\":%s,\"call_depth\":%u,"
        "\"module\":\"%s\",\"symbol\":\"%s\","
        "\"function_address\":\"0x%" PRIxPTR "\","
        "\"module_base\":\"0x%" PRIxPTR "\","
        "\"module_offset\":\"0x%" PRIxPTR "\","
        "\"call_site_address\":\"0x%" PRIxPTR "\","
        "\"module_device\":%ju,\"module_inode\":%ju,"
        "\"module_size\":%jd,\"module_mtime_ns\":%lld}",
        CXS_SCHEMA,
        kind,
        (long)getpid(),
        (long)getppid(),
        cxs_instance,
        cxs_thread_id(),
        process_seq,
        monotonic_ns,
        wall_time_ns,
        cxs_instance,
        cxs_thread_id(),
        frame->activation,
        parent,
        frame->depth,
        escaped_path,
        escaped_symbol,
        module->address,
        module->base,
        module->offset,
        (uintptr_t)call_site,
        (uintmax_t)module->device,
        (uintmax_t)module->inode,
        (intmax_t)module->size,
        module->mtime_ns
    );
    if (length > 0 && (size_t)length < sizeof(payload)) {
        cxs_send(payload, (size_t)length);
    } else {
        atomic_fetch_add_explicit(&cxs_dropped, 1ULL, memory_order_relaxed);
    }
}

static CXS_NOINSTRUMENT void cxs_profile_func_enter(
    void *function, void *call_site
) {
    struct cxs_module module;
    struct cxs_frame frame;
    unsigned long long activation;
    unsigned long long monotonic_ns;
    unsigned long long wall_time_ns;
    (void)pthread_once(&cxs_once, cxs_initialize);
    if (!cxs_enabled) {
        return;
    }
    cxs_refresh_after_fork();
    monotonic_ns = cxs_clock_ns(CLOCK_MONOTONIC);
    wall_time_ns = cxs_clock_ns(CLOCK_REALTIME);
    if (!cxs_module_for(function, &module)) {
        return;
    }
    if (cxs_depth >= CXS_STACK_LIMIT) {
        ++cxs_suppressed_depth;
        return;
    }
    activation = atomic_fetch_add_explicit(&cxs_calls, 1ULL, memory_order_relaxed) + 1ULL;
    if (activation > cxs_max_calls) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &cxs_limit_sent,
                &expected,
                1,
                memory_order_relaxed,
                memory_order_relaxed
            )) {
            cxs_send_control("limit_reached");
        }
        ++cxs_suppressed_depth;
        return;
    }
    frame.function = function;
    frame.activation = activation;
    frame.parent = cxs_depth == 0U ? 0ULL : cxs_stack[cxs_depth - 1U].activation;
    frame.depth = cxs_depth;
    cxs_stack[cxs_depth++] = frame;
    cxs_send_frame(
        "frame_enter", &module, &frame, call_site, monotonic_ns, wall_time_ns
    );
}

static CXS_NOINSTRUMENT void cxs_profile_func_exit(
    void *function, void *call_site
) {
    struct cxs_module module;
    struct cxs_frame frame;
    unsigned int index;
    unsigned long long monotonic_ns;
    unsigned long long wall_time_ns;
    (void)pthread_once(&cxs_once, cxs_initialize);
    if (!cxs_enabled) {
        return;
    }
    cxs_refresh_after_fork();
    monotonic_ns = cxs_clock_ns(CLOCK_MONOTONIC);
    wall_time_ns = cxs_clock_ns(CLOCK_REALTIME);
    if (!cxs_module_for(function, &module)) {
        return;
    }
    if (cxs_suppressed_depth > 0U) {
        --cxs_suppressed_depth;
        return;
    }
    if (cxs_depth == 0U) {
        return;
    }
    index = cxs_depth;
    while (index > 0U && cxs_stack[index - 1U].function != function) {
        --index;
    }
    if (index == 0U) {
        return;
    }
    frame = cxs_stack[index - 1U];
    cxs_depth = index - 1U;
    cxs_send_frame(
        "frame_exit", &module, &frame, call_site, monotonic_ns, wall_time_ns
    );
}

void CXS_NOINSTRUMENT __cyg_profile_func_enter(void *function, void *call_site) {
    int saved_errno;
    if (cxs_in_callback != 0U) {
        return;
    }
    /* Set the guard before pthread_once and every interposable libc call. */
    cxs_in_callback = 1U;
    saved_errno = errno;
    cxs_profile_func_enter(function, call_site);
    errno = saved_errno;
    cxs_in_callback = 0U;
}

void CXS_NOINSTRUMENT __cyg_profile_func_exit(void *function, void *call_site) {
    int saved_errno;
    if (cxs_in_callback != 0U) {
        return;
    }
    cxs_in_callback = 1U;
    saved_errno = errno;
    cxs_profile_func_exit(function, call_site);
    errno = saved_errno;
    cxs_in_callback = 0U;
}
