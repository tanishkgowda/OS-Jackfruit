/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Architecture:
 *   - One long-running "supervisor" process owns the UNIX socket,
 *     the logging pipeline, and the container metadata list.
 *   - Every other invocation (start / run / ps / logs / stop) is a
 *     short-lived "client" that connects to the socket, sends one
 *     control_request_t, reads one control_response_t, and exits.
 *
 * IPC paths:
 *   Path A (logging):  container stdout/stderr → pipe → supervisor
 *                      producer thread → bounded_buffer → consumer
 *                      thread → per-container log file
 *   Path B (control):  CLI client → UNIX domain socket → supervisor
 *
 * Signal handling:
 *   SIGCHLD  – reaped in the supervisor event loop via waitpid(-1,WNOHANG)
 *   SIGINT / SIGTERM – set a global flag; supervisor drains and exits
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define STACK_SIZE           (1024 * 1024)
#define CONTAINER_ID_LEN     32
#define CONTROL_PATH         "/tmp/mini_runtime.sock"
#define LOG_DIR              "logs"
#define CONTROL_MESSAGE_LEN  4096
#define CHILD_COMMAND_LEN    256
#define LOG_CHUNK_SIZE       4096
#define LOG_BUFFER_CAPACITY  16
#define DEFAULT_SOFT_LIMIT   (40UL << 20)
#define DEFAULT_HARD_LIMIT   (64UL << 20)

/* ------------------------------------------------------------------ */
/*  Enumerations                                                        */
/* ------------------------------------------------------------------ */
typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED,
    CONTAINER_HARD_LIMIT_KILLED
} container_state_t;

/* ------------------------------------------------------------------ */
/*  Data structures                                                     */
/* ------------------------------------------------------------------ */

/* One entry per tracked container */
typedef struct container_record {
    char              id[CONTAINER_ID_LEN];
    pid_t             host_pid;
    time_t            started_at;
    container_state_t state;
    unsigned long     soft_limit_bytes;
    unsigned long     hard_limit_bytes;
    int               exit_code;
    int               exit_signal;
    int               stop_requested;   /* set before sending SIGTERM */
    char              log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

/* One slot in the bounded log buffer */
typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

/* Bounded producer-consumer buffer */
typedef struct {
    log_item_t        items[LOG_BUFFER_CAPACITY];
    size_t            head;
    size_t            tail;
    size_t            count;
    int               shutting_down;
    pthread_mutex_t   mutex;
    pthread_cond_t    not_empty;
    pthread_cond_t    not_full;
} bounded_buffer_t;

/* Message sent from CLI client → supervisor */
typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
    int            is_run;   /* 1 when CMD_RUN so supervisor knows to wait */
} control_request_t;

/* Message sent from supervisor → CLI client */
typedef struct {
    int  status;               /* 0 = ok, non-zero = error */
    int  container_exit_code;  /* used by CMD_RUN */
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

/* Arguments passed into the cloned child process */
typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  log_write_fd;  /* write end of the log pipe */
} child_config_t;

/* Per-producer-thread argument */
typedef struct {
    int             pipe_read_fd;
    char            container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *buffer;
} producer_arg_t;

/* Global supervisor state */
typedef struct {
    int               server_fd;
    int               monitor_fd;
    int               should_stop;
    bounded_buffer_t  log_buffer;
    pthread_mutex_t   metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* ------------------------------------------------------------------ */
/*  Globals (supervisor only)                                           */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_signal_received = 0;
static supervisor_ctx_t     *g_ctx             = NULL;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                                */
/* ------------------------------------------------------------------ */
static void usage(const char *prog);
static int  parse_mib_flag(const char *flag, const char *value,
                            unsigned long *target_bytes);
static int  parse_optional_flags(control_request_t *req, int argc,
                                  char *argv[], int start_index);
static const char *state_to_string(container_state_t state);

/* ------------------------------------------------------------------ */
/*  Bounded-buffer implementation                                       */
/* ------------------------------------------------------------------ */

static int bounded_buffer_init(bounded_buffer_t *buf)
{
    int rc;
    memset(buf, 0, sizeof(*buf));

    rc = pthread_mutex_init(&buf->mutex, NULL);
    if (rc != 0) return rc;

    rc = pthread_cond_init(&buf->not_empty, NULL);
    if (rc != 0) { pthread_mutex_destroy(&buf->mutex); return rc; }

    rc = pthread_cond_init(&buf->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buf->not_empty);
        pthread_mutex_destroy(&buf->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buf)
{
    pthread_cond_destroy(&buf->not_full);
    pthread_cond_destroy(&buf->not_empty);
    pthread_mutex_destroy(&buf->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buf)
{
    pthread_mutex_lock(&buf->mutex);
    buf->shutting_down = 1;
    pthread_cond_broadcast(&buf->not_empty);
    pthread_cond_broadcast(&buf->not_full);
    pthread_mutex_unlock(&buf->mutex);
}

/*
 * bounded_buffer_push  – producer side
 *
 * Blocks while the buffer is full (unless shutting down).
 * Returns  0 on success
 *         -1 if shutting down and there is no room
 */
int bounded_buffer_push(bounded_buffer_t *buf, const log_item_t *item)
{
    pthread_mutex_lock(&buf->mutex);

    while (buf->count == LOG_BUFFER_CAPACITY && !buf->shutting_down)
        pthread_cond_wait(&buf->not_full, &buf->mutex);

    if (buf->count == LOG_BUFFER_CAPACITY) {
        /* Buffer full and we are shutting down – drop the item */
        pthread_mutex_unlock(&buf->mutex);
        return -1;
    }

    buf->items[buf->tail] = *item;
    buf->tail = (buf->tail + 1) % LOG_BUFFER_CAPACITY;
    buf->count++;

    pthread_cond_signal(&buf->not_empty);
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

/*
 * bounded_buffer_pop  – consumer side
 *
 * Blocks while the buffer is empty and not shutting down.
 * Returns  0 on success (item filled in)
 *          1 if shutting down and the buffer is empty (consumer should exit)
 */
int bounded_buffer_pop(bounded_buffer_t *buf, log_item_t *item)
{
    pthread_mutex_lock(&buf->mutex);

    while (buf->count == 0 && !buf->shutting_down)
        pthread_cond_wait(&buf->not_empty, &buf->mutex);

    if (buf->count == 0) {
        /* Shutdown signalled and buffer drained */
        pthread_mutex_unlock(&buf->mutex);
        return 1;
    }

    *item = buf->items[buf->head];
    buf->head = (buf->head + 1) % LOG_BUFFER_CAPACITY;
    buf->count--;

    pthread_cond_signal(&buf->not_full);
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Logging consumer thread                                             */
/* ------------------------------------------------------------------ */

/*
 * logging_thread  – one thread, shared by all containers.
 *
 * Pops items from the bounded buffer and appends them to the
 * per-container log file.  Exits when pop() signals shutdown+empty.
 */
void *logging_thread(void *arg)
{
    bounded_buffer_t *buf = (bounded_buffer_t *)arg;
    log_item_t        item;
    int               rc;

    while ((rc = bounded_buffer_pop(buf, &item)) == 0) {
        /* Build the log file path: logs/<container_id>.log */
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            perror("logging_thread: open log file");
            continue;
        }
        if (write(fd, item.data, item.length) < 0)
            perror("logging_thread: write");
        close(fd);
    }

    /* rc == 1 means shutdown + empty — we are done */
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Producer thread (one per container)                                 */
/* ------------------------------------------------------------------ */

/*
 * producer_thread  – reads from the container pipe and pushes into
 * the shared bounded buffer.  Exits when the pipe EOF is reached
 * (container exited / pipe closed).
 */
static void *producer_thread(void *arg)
{
    producer_arg_t *pa  = (producer_arg_t *)arg;
    log_item_t      item;
    ssize_t         n;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, pa->container_id, CONTAINER_ID_LEN - 1);

    while ((n = read(pa->pipe_read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        bounded_buffer_push(pa->buffer, &item);
        memset(item.data, 0, LOG_CHUNK_SIZE);
    }

    close(pa->pipe_read_fd);
    free(pa);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Container child entrypoint (runs inside clone())                   */
/* ------------------------------------------------------------------ */

/*
 * child_fn  – called in the new namespace after clone().
 *
 * Steps:
 *  1. chroot into the container rootfs
 *  2. mount /proc so ps/top work
 *  3. redirect stdout and stderr to the pipe write-end
 *  4. apply nice value
 *  5. exec the requested command
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* Set hostname to container ID (UTS namespace) */
    if (sethostname(cfg->id, strlen(cfg->id)) < 0)
        perror("sethostname");

    /* chroot into the container's root filesystem */
    if (chroot(cfg->rootfs) < 0) {
        perror("chroot");
        return 1;
    }
    if (chdir("/") < 0) {
        perror("chdir /");
        return 1;
    }

    /* Mount /proc inside the container */
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        perror("mount /proc");   /* non-fatal – continue */

    /* Redirect stdout and stderr to the log pipe */
    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }

    /* Apply nice priority */
    if (cfg->nice_value != 0)
        if (nice(cfg->nice_value) == -1 && errno != 0) perror("nice");

    /* Exec the command – split on the first space for argv[1] */
    char *cmd  = cfg->command;
    char *args[4];
    args[0] = "/bin/sh";
    args[1] = "-c";
    args[2] = cmd;
    args[3] = NULL;
    execv("/bin/sh", args);

    perror("execv");
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Monitor ioctl helpers                                               */
/* ------------------------------------------------------------------ */

int register_with_monitor(int monitor_fd, const char *container_id,
                           pid_t host_pid, unsigned long soft_limit_bytes,
                           unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid               = host_pid;
    req.soft_limit_bytes  = soft_limit_bytes;
    req.hard_limit_bytes  = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id,
                             pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Metadata helpers (all called with metadata_lock held)              */
/* ------------------------------------------------------------------ */

static container_record_t *find_container(supervisor_ctx_t *ctx,
                                           const char *id)
{
    container_record_t *r;
    for (r = ctx->containers; r; r = r->next)
        if (strcmp(r->id, id) == 0)
            return r;
    return NULL;
}

static container_record_t *find_container_by_pid(supervisor_ctx_t *ctx,
                                                   pid_t pid)
{
    container_record_t *r;
    for (r = ctx->containers; r; r = r->next)
        if (r->host_pid == pid)
            return r;
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Signal handlers                                                     */
/* ------------------------------------------------------------------ */

static void handle_sigchld(int sig)
{
    (void)sig;
    /* Actual reaping is done in the event loop */
    g_signal_received = 1;
}

static void handle_shutdown(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

/* ------------------------------------------------------------------ */
/*  Supervisor: launch a new container                                  */
/* ------------------------------------------------------------------ */

/*
 * launch_container  – allocates stack, clones a new child with
 * PID/UTS/mount namespaces, registers it with the kernel monitor,
 * and starts a producer thread to forward its output.
 *
 * Returns 0 on success, -1 on error.
 */
static int launch_container(supervisor_ctx_t *ctx,
                             const control_request_t *req,
                             control_response_t *resp)
{
    int pipefd[2];
    char *stack, *stack_top;
    pid_t child_pid;
    child_config_t *cfg;
    container_record_t *rec;
    producer_arg_t *pa;
    pthread_t prod_tid;

    /* Ensure container ID is unique */
    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container(ctx, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(resp->message, CONTROL_MESSAGE_LEN,
                 "Container '%s' already exists", req->container_id);
        resp->status = -1;
        return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Create log directory if missing */
    mkdir(LOG_DIR, 0755);

    /* Pipe: container stdout/stderr → supervisor */
    if (pipe(pipefd) < 0) {
        perror("pipe");
        resp->status = -1;
        snprintf(resp->message, CONTROL_MESSAGE_LEN, "pipe() failed: %s",
                 strerror(errno));
        return -1;
    }

    /* Build child config */
    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        close(pipefd[0]); close(pipefd[1]);
        resp->status = -1;
        snprintf(resp->message, CONTROL_MESSAGE_LEN, "calloc failed");
        return -1;
    }
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,        PATH_MAX - 1);
    strncpy(cfg->command, req->command,       CHILD_COMMAND_LEN - 1);
    cfg->nice_value   = req->nice_value;
    cfg->log_write_fd = pipefd[1];

    /* Allocate clone stack */
    stack = malloc(STACK_SIZE);
    if (!stack) {
        free(cfg);
        close(pipefd[0]); close(pipefd[1]);
        resp->status = -1;
        snprintf(resp->message, CONTROL_MESSAGE_LEN, "malloc stack failed");
        return -1;
    }
    stack_top = stack + STACK_SIZE;

    /* Clone with PID, UTS, and mount namespace isolation */
    child_pid = clone(child_fn, stack_top,
                      CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                      cfg);

    /* Close the write end in the supervisor after clone */
    close(pipefd[1]);

    if (child_pid < 0) {
        perror("clone");
        free(stack);
        free(cfg);
        close(pipefd[0]);
        resp->status = -1;
        snprintf(resp->message, CONTROL_MESSAGE_LEN, "clone() failed: %s",
                 strerror(errno));
        return -1;
    }

    /* Register metadata */
    rec = calloc(1, sizeof(*rec));
    if (!rec) {
        /* kill the child we just created */
        kill(child_pid, SIGKILL);
        free(stack);
        free(cfg);
        close(pipefd[0]);
        resp->status = -1;
        snprintf(resp->message, CONTROL_MESSAGE_LEN, "calloc rec failed");
        return -1;
    }
    strncpy(rec->id, req->container_id, CONTAINER_ID_LEN - 1);
    rec->host_pid          = child_pid;
    rec->started_at        = time(NULL);
    rec->state             = CONTAINER_RUNNING;
    rec->soft_limit_bytes  = req->soft_limit_bytes;
    rec->hard_limit_bytes  = req->hard_limit_bytes;
    snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, req->container_id);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next       = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Register with kernel monitor (best-effort) */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, req->container_id, child_pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    /* Start producer thread for this container's pipe */
    pa = calloc(1, sizeof(*pa));
    if (pa) {
        pa->pipe_read_fd = pipefd[0];
        pa->buffer       = &ctx->log_buffer;
        strncpy(pa->container_id, req->container_id, CONTAINER_ID_LEN - 1);
        if (pthread_create(&prod_tid, NULL, producer_thread, pa) != 0) {
            free(pa);
            close(pipefd[0]);
        } else {
            pthread_detach(prod_tid);
        }
    } else {
        close(pipefd[0]);
    }

    free(stack);

    resp->status = 0;
    snprintf(resp->message, CONTROL_MESSAGE_LEN,
             "Started container '%s' pid=%d", req->container_id, child_pid);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Supervisor: handle one CLI request                                  */
/* ------------------------------------------------------------------ */

static void handle_request(supervisor_ctx_t *ctx,
                            int client_fd,
                            const control_request_t *req)
{
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));

    switch (req->kind) {

    case CMD_START:
    case CMD_RUN: {
        launch_container(ctx, req, &resp);

        if (req->kind == CMD_RUN && resp.status == 0) {
            /* Block until the container exits */
            pid_t target_pid;
            container_record_t *r;

            pthread_mutex_lock(&ctx->metadata_lock);
            r = find_container(ctx, req->container_id);
            target_pid = r ? r->host_pid : -1;
            pthread_mutex_unlock(&ctx->metadata_lock);

            if (target_pid > 0) {
                int wstatus;
                waitpid(target_pid, &wstatus, 0);

                pthread_mutex_lock(&ctx->metadata_lock);
                r = find_container(ctx, req->container_id);
                if (r) {
                    if (WIFEXITED(wstatus)) {
                        r->exit_code = WEXITSTATUS(wstatus);
                        r->state     = CONTAINER_EXITED;
                        resp.container_exit_code = r->exit_code;
                    } else if (WIFSIGNALED(wstatus)) {
                        r->exit_signal = WTERMSIG(wstatus);
                        r->exit_code   = 128 + r->exit_signal;
                        r->state = r->stop_requested
                                 ? CONTAINER_STOPPED
                                 : (r->exit_signal == SIGKILL
                                    ? CONTAINER_HARD_LIMIT_KILLED
                                    : CONTAINER_KILLED);
                        resp.container_exit_code = r->exit_code;
                    }
                }
                pthread_mutex_unlock(&ctx->metadata_lock);

                if (ctx->monitor_fd >= 0)
                    unregister_from_monitor(ctx->monitor_fd,
                                            req->container_id, target_pid);
            }
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "Container '%s' exited with code %d",
                     req->container_id, resp.container_exit_code);
        }
        break;
    }

    case CMD_STOP: {
        container_record_t *r;

        pthread_mutex_lock(&ctx->metadata_lock);
        r = find_container(ctx, req->container_id);
        if (!r) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "Container '%s' not found", req->container_id);
            break;
        }
        if (r->state != CONTAINER_RUNNING) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "Container '%s' is not running", req->container_id);
            break;
        }
        r->stop_requested = 1;
        pid_t pid = r->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);

        /* Graceful: SIGTERM first, then SIGKILL after 3 s */
        kill(pid, SIGTERM);
        struct timespec ts = {3, 0};
        nanosleep(&ts, NULL);

        pthread_mutex_lock(&ctx->metadata_lock);
        r = find_container(ctx, req->container_id);
        if (r && r->state == CONTAINER_RUNNING) {
            kill(pid, SIGKILL);
            r->state = CONTAINER_STOPPED;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        resp.status = 0;
        snprintf(resp.message, CONTROL_MESSAGE_LEN,
                 "Stopped container '%s'", req->container_id);
        break;
    }

    case CMD_PS: {
        container_record_t *r;
        char line[256];
        int  off = 0;

        /* Build a multi-line response in resp.message */
        snprintf(resp.message, CONTROL_MESSAGE_LEN,
                 "%-16s %-8s %-10s %-20s\n",
                 "ID", "PID", "STATE", "STARTED");
        off = (int)strlen(resp.message);

        pthread_mutex_lock(&ctx->metadata_lock);
        for (r = ctx->containers; r && off < CONTROL_MESSAGE_LEN - 2; r = r->next) {
            char tsbuf[32];
            struct tm *tm_info = localtime(&r->started_at);
            strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", tm_info);

            snprintf(line, sizeof(line), "%-16s %-8d %-10s %-20s\n",
                     r->id, r->host_pid, state_to_string(r->state), tsbuf);
            int remain = CONTROL_MESSAGE_LEN - off - 1;
            int n = remain < (int)strlen(line) ? remain : (int)strlen(line);
            memcpy(resp.message + off, line, n);
            off += n;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.message[off] = '\0';
        resp.status = 0;
        break;
    }

    case CMD_LOGS: {
        container_record_t *r;
        char log_path[PATH_MAX];

        pthread_mutex_lock(&ctx->metadata_lock);
        r = find_container(ctx, req->container_id);
        if (r)
            strncpy(log_path, r->log_path, PATH_MAX - 1);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!r) {
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "Container '%s' not found", req->container_id);
            break;
        }

        /* Read up to CONTROL_MESSAGE_LEN bytes from the log file */
        int fd = open(log_path, O_RDONLY);
        if (fd < 0) {
            resp.status = -1;
            snprintf(resp.message, CONTROL_MESSAGE_LEN,
                     "Cannot open log: %s", strerror(errno));
            break;
        }
        ssize_t n = read(fd, resp.message, CONTROL_MESSAGE_LEN - 1);
        if (n < 0) n = 0;
        resp.message[n] = '\0';
        close(fd);
        resp.status = 0;
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, CONTROL_MESSAGE_LEN, "Unknown command");
        break;
    }

    /* Send response back to the CLI client */
    if (write(client_fd, &resp, sizeof(resp)) < 0) perror("write response");
}

/* ------------------------------------------------------------------ */
/*  Supervisor: reap exited children                                    */
/* ------------------------------------------------------------------ */

static void reap_children(supervisor_ctx_t *ctx)
{
    int wstatus;
    pid_t pid;

    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        container_record_t *r;

        pthread_mutex_lock(&ctx->metadata_lock);
        r = find_container_by_pid(ctx, pid);
        if (r) {
            if (WIFEXITED(wstatus)) {
                r->exit_code = WEXITSTATUS(wstatus);
                r->state     = CONTAINER_EXITED;
            } else if (WIFSIGNALED(wstatus)) {
                r->exit_signal = WTERMSIG(wstatus);
                r->exit_code   = 128 + r->exit_signal;
                r->state = r->stop_requested ? CONTAINER_STOPPED
                                              : (r->exit_signal == SIGKILL
                                                 ? CONTAINER_HARD_LIMIT_KILLED
                                                 : CONTAINER_KILLED);
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (ctx->monitor_fd >= 0 && r)
            unregister_from_monitor(ctx->monitor_fd, r->id, pid);
    }
}

/* ------------------------------------------------------------------ */
/*  Supervisor main                                                     */
/* ------------------------------------------------------------------ */

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    pthread_t logger_tid;
    int rc;

    (void)rootfs;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx          = &ctx;

    /* Mutex for metadata */
    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    /* Bounded buffer */
    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc; perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    /* Log directory */
    mkdir(LOG_DIR, 0755);

    /* Open kernel monitor device (optional) */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "Warning: cannot open /dev/container_monitor "
                        "(kernel module not loaded?)\n");

    /* Create UNIX domain socket for CLI control channel */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); goto cleanup; }

    unlink(CONTROL_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); goto cleanup;
    }
    if (listen(ctx.server_fd, 8) < 0) { perror("listen"); goto cleanup; }

    /* Signal handlers */
    {
        struct sigaction sa_chld, sa_term;

        memset(&sa_chld, 0, sizeof(sa_chld));
        sa_chld.sa_handler = handle_sigchld;
        sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa_chld, NULL);

        memset(&sa_term, 0, sizeof(sa_term));
        sa_term.sa_handler = handle_shutdown;
        sigaction(SIGINT,  &sa_term, NULL);
        sigaction(SIGTERM, &sa_term, NULL);
    }

    /* Start logging consumer thread */
    if (pthread_create(&logger_tid, NULL, logging_thread, &ctx.log_buffer)) {
        perror("pthread_create logger");
        goto cleanup;
    }

    fprintf(stderr, "Supervisor ready. Control socket: %s\n", CONTROL_PATH);

    /* Event loop */
    while (!ctx.should_stop) {
        fd_set rfds;
        struct timeval tv = {1, 0};  /* 1 second timeout for signal check */
        int nfds;

        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        nfds = ctx.server_fd + 1;

        int sel = select(nfds, &rfds, NULL, NULL, &tv);

        /* Reap any children that exited */
        if (g_signal_received) {
            g_signal_received = 0;
            reap_children(&ctx);
        }

        if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (sel == 0) continue;  /* timeout */

        if (FD_ISSET(ctx.server_fd, &rfds)) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                continue;
            }

            control_request_t req;
            ssize_t n = read(client_fd, &req, sizeof(req));
            if (n == (ssize_t)sizeof(req)) {
                handle_request(&ctx, client_fd, &req);
            }
            close(client_fd);
        }
    }

    fprintf(stderr, "Supervisor shutting down...\n");

    /* Kill all running containers */
    {
        container_record_t *r;
        pthread_mutex_lock(&ctx.metadata_lock);
        for (r = ctx.containers; r; r = r->next)
            if (r->state == CONTAINER_RUNNING)
                kill(r->host_pid, SIGTERM);
        pthread_mutex_unlock(&ctx.metadata_lock);

        /* Give them a moment, then reap */
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        reap_children(&ctx);
    }

    /* Shut down logging pipeline */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(logger_tid, NULL);

cleanup:
    if (ctx.server_fd >= 0) { close(ctx.server_fd); unlink(CONTROL_PATH); }
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);

    /* Free metadata list */
    {
        container_record_t *r = ctx.containers, *next;
        while (r) { next = r->next; free(r); r = next; }
    }

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  CLI client: send a request and print the response                   */
/* ------------------------------------------------------------------ */

/* Global for SIGINT forwarding in CMD_RUN */
static volatile sig_atomic_t g_run_interrupted = 0;
static char g_run_container_id[CONTAINER_ID_LEN] = {0};

static void handle_run_sigint(int sig)
{
    (void)sig;
    g_run_interrupted = 1;
}

static int send_stop_to_supervisor(const char *container_id)
{
    control_request_t stop_req;
    control_response_t stop_resp;
    struct sockaddr_un addr;
    int fd2;

    memset(&stop_req, 0, sizeof(stop_req));
    stop_req.kind = CMD_STOP;
    strncpy(stop_req.container_id, container_id, CONTAINER_ID_LEN - 1);

    fd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd2 < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd2, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd2); return -1;
    }
    if (write(fd2, &stop_req, sizeof(stop_req)) != (ssize_t)sizeof(stop_req)) {
        close(fd2); return -1;
    }
    if (read(fd2, &stop_resp, sizeof(stop_resp)) < 0) { /* best effort */ }
    close(fd2);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;
    ssize_t n;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect (is the supervisor running?)");
        close(fd);
        return 1;
    }

    if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write request");
        close(fd);
        return 1;
    }

    /* For CMD_RUN: install SIGINT/SIGTERM handler that forwards stop */
    if (req->kind == CMD_RUN) {
        struct sigaction sa;
        strncpy(g_run_container_id, req->container_id, CONTAINER_ID_LEN - 1);
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_run_sigint;
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }

    n = read(fd, &resp, sizeof(resp));
    close(fd);

    /* If interrupted during run, forward stop and continue waiting */
    if (req->kind == CMD_RUN && g_run_interrupted) {
        fprintf(stderr, "\nInterrupted — stopping container '%s'...\n",
                g_run_container_id);
        send_stop_to_supervisor(g_run_container_id);
    }

    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "Incomplete response from supervisor\n");
        return 1;
    }

    if (resp.message[0])
        printf("%s\n", resp.message);

    return resp.status == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  CLI sub-commands                                                    */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> "
            "[--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> "
            "[--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value,
                           unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib   = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc,
                                  char *argv[], int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char  *end = NULL;
        long   nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i+1],
                               &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i+1],
                               &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i+1], &end, 10);
            if (errno != 0 || end == argv[i+1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i+1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:             return "exited";
    case CONTAINER_HARD_LIMIT_KILLED:  return "hard_limit_killed";
    default:                           return "unknown";
    }
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s start <id> <rootfs> <cmd> [...]\n",
                argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind              = CMD_START;
    req.soft_limit_bytes  = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes  = DEFAULT_HARD_LIMIT;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    strncpy(req.rootfs,       argv[3], PATH_MAX - 1);
    strncpy(req.command,      argv[4], CHILD_COMMAND_LEN - 1);
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s run <id> <rootfs> <cmd> [...]\n",
                argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind              = CMD_RUN;
    req.soft_limit_bytes  = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes  = DEFAULT_HARD_LIMIT;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    strncpy(req.rootfs,       argv[3], PATH_MAX - 1);
    strncpy(req.command,      argv[4], CHILD_COMMAND_LEN - 1);
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    return send_control_request(&req);
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}