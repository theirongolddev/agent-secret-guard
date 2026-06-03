#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ASG_MAX_BODY ((uint64_t)64 * 1024 * 1024)
#define ASG_DEFAULT_CLI "/Users/tayloreernisse/.local/bin/agent-secret-guard"
#define ASG_DEFAULT_SOCKET "/Users/tayloreernisse/.local/run/agent-secret-guard/asg.sock"
#define ASG_DEFAULT_DAEMON_TIMEOUT_MS 400
#define ASG_DEFAULT_FALLBACK_TIMEOUT_MS 2000
#define ASG_DEFAULT_CIRCUIT_SECONDS 60

struct buffer {
  unsigned char *data;
  size_t len;
  size_t cap;
};

static void buffer_free(struct buffer *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static uint64_t host_to_be64(uint64_t value) {
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    result = (result << 8) | (value & 0xff);
    value >>= 8;
  }
  return result;
}

static uint64_t be64_to_host(uint64_t value) {
  return host_to_be64(value);
}

static int buffer_reserve(struct buffer *buf, size_t extra) {
  if (extra > SIZE_MAX - buf->len) {
    return -1;
  }
  size_t needed = buf->len + extra;
  if (needed <= buf->cap) {
    return 0;
  }
  size_t next = buf->cap ? buf->cap : 4096;
  while (next < needed) {
    if (next > SIZE_MAX / 2) {
      next = needed;
      break;
    }
    next *= 2;
  }
  unsigned char *data = malloc(next);
  if (!data) {
    return -1;
  }
  if (buf->len) {
    memcpy(data, buf->data, buf->len);
  }
  free(buf->data);
  buf->data = data;
  buf->cap = next;
  return 0;
}

static int buffer_append(struct buffer *buf, const void *data, size_t len) {
  if (buffer_reserve(buf, len) != 0) {
    return -1;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  return 0;
}

static int read_stdin_all(struct buffer *buf) {
  unsigned char chunk[65536];
  for (;;) {
    ssize_t n = read(STDIN_FILENO, chunk, sizeof(chunk));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return 0;
    }
    if ((uint64_t)buf->len + (uint64_t)n > ASG_MAX_BODY) {
      return -1;
    }
    if (buffer_append(buf, chunk, (size_t)n) != 0) {
      return -1;
    }
  }
}

static int write_all_fd(int fd, const void *data, size_t len) {
  const unsigned char *cursor = (const unsigned char *)data;
  while (len) {
    ssize_t n = write(fd, cursor, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    cursor += n;
    len -= (size_t)n;
  }
  return 0;
}

static long long now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return ((long long)tv.tv_sec * 1000LL) + ((long long)tv.tv_usec / 1000LL);
}

static int wait_for_fd(int fd, short events, long long deadline_ms) {
  for (;;) {
    long long remaining = deadline_ms - now_ms();
    if (remaining <= 0) {
      return -1;
    }
    struct pollfd pfd = {.fd = fd, .events = events};
    int polled = poll(&pfd, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
    if (polled > 0) {
      if (pfd.revents & events) {
        return 0;
      }
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return -1;
      }
    } else if (polled == 0) {
      return -1;
    } else if (errno != EINTR) {
      return -1;
    }
  }
}

static int write_all_fd_until(int fd, const void *data, size_t len, long long deadline_ms) {
  const unsigned char *cursor = (const unsigned char *)data;
  while (len) {
    ssize_t n = write(fd, cursor, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (wait_for_fd(fd, POLLOUT, deadline_ms) != 0) {
          return -1;
        }
        continue;
      }
      return -1;
    }
    cursor += n;
    len -= (size_t)n;
  }
  return 0;
}

static int read_exact_fd(int fd, void *data, size_t len) {
  unsigned char *cursor = (unsigned char *)data;
  while (len) {
    ssize_t n = read(fd, cursor, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    cursor += n;
    len -= (size_t)n;
  }
  return 0;
}

static int stream_exact_to_fd(int in_fd, int out_fd, uint64_t len) {
  unsigned char chunk[65536];
  while (len) {
    size_t want = len > sizeof(chunk) ? sizeof(chunk) : (size_t)len;
    if (read_exact_fd(in_fd, chunk, want) != 0) {
      return -1;
    }
    if (write_all_fd(out_fd, chunk, want) != 0) {
      return -1;
    }
    len -= want;
  }
  return 0;
}

static char *home_join(const char *suffix) {
  const char *home = getenv("HOME");
  if (!home || !*home) {
    return NULL;
  }
  size_t home_len = strlen(home);
  size_t suffix_len = strlen(suffix);
  char *path = malloc(home_len + suffix_len + 1);
  if (!path) {
    return NULL;
  }
  memcpy(path, home, home_len);
  memcpy(path + home_len, suffix, suffix_len + 1);
  return path;
}

static char *socket_path(void) {
  const char *configured = getenv("ASG_DAEMON_SOCKET");
  if (configured && *configured) {
    return strdup(configured);
  }
  char *home_path = home_join("/.local/run/agent-secret-guard/asg.sock");
  return home_path ? home_path : strdup(ASG_DEFAULT_SOCKET);
}

static char *cli_path(void) {
  const char *configured = getenv("ASG_AGENT_SECRET_GUARD");
  if (configured && *configured) {
    return strdup(configured);
  }
  char *home_path = home_join("/.local/bin/agent-secret-guard");
  return home_path ? home_path : strdup(ASG_DEFAULT_CLI);
}

static char *circuit_path(void) {
  const char *configured = getenv("ASG_FAST_CIRCUIT_PATH");
  if (configured && *configured) {
    return strdup(configured);
  }
  const char *configured_socket = getenv("ASG_DAEMON_SOCKET");
  if (configured_socket && *configured_socket) {
    const char *suffix = ".unhealthy-until";
    size_t socket_len = strlen(configured_socket);
    size_t suffix_len = strlen(suffix);
    char *path = malloc(socket_len + suffix_len + 1);
    if (!path) {
      return NULL;
    }
    memcpy(path, configured_socket, socket_len);
    memcpy(path + socket_len, suffix, suffix_len + 1);
    return path;
  }
  char *home_path = home_join("/.local/run/agent-secret-guard/asg-unhealthy-until");
  return home_path ? home_path : NULL;
}

static int env_int(const char *name, int fallback, int min_value, int max_value) {
  const char *raw = getenv(name);
  if (!raw || !*raw) {
    return fallback;
  }
  char *end = NULL;
  long parsed = strtol(raw, &end, 10);
  if (!end || *end || parsed < min_value || parsed > max_value) {
    return fallback;
  }
  return (int)parsed;
}

static int daemon_timeout_ms(void) {
  return env_int("ASG_FAST_DAEMON_TIMEOUT_MS", ASG_DEFAULT_DAEMON_TIMEOUT_MS, 50, 5000);
}

static int fallback_timeout_ms(void) {
  return env_int("ASG_FAST_FALLBACK_TIMEOUT_MS", ASG_DEFAULT_FALLBACK_TIMEOUT_MS, 250, 30000);
}

static int circuit_seconds(void) {
  return env_int("ASG_FAST_CIRCUIT_SECONDS", ASG_DEFAULT_CIRCUIT_SECONDS, 1, 3600);
}

static int circuit_is_open(void) {
  char *path = circuit_path();
  if (!path) {
    return 0;
  }
  FILE *fp = fopen(path, "r");
  free(path);
  if (!fp) {
    return 0;
  }
  long until = 0;
  int parsed = fscanf(fp, "%ld", &until);
  fclose(fp);
  return parsed == 1 && until > (long)time(NULL);
}

static void mark_circuit_unhealthy(void) {
  char *path = circuit_path();
  if (!path) {
    return;
  }
  FILE *fp = fopen(path, "w");
  if (!fp) {
    free(path);
    return;
  }
  fprintf(fp, "%ld\n", (long)time(NULL) + circuit_seconds());
  fclose(fp);
  free(path);
}

static int set_fd_deadlines(int fd, int timeout_ms) {
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int ok = 0;
  ok |= setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ok |= setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  return ok;
}

static int connect_socket(const char *path, int timeout_ms) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  if (set_fd_deadlines(fd, timeout_ms) != 0) {
    close(fd);
    return -1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    close(fd);
    return -1;
  }
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    close(fd);
    return -1;
  }
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    if (errno != EINPROGRESS) {
      close(fd);
      return -1;
    }
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    int polled;
    do {
      polled = poll(&pfd, 1, timeout_ms);
    } while (polled < 0 && errno == EINTR);
    if (polled <= 0) {
      close(fd);
      return -1;
    }
    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0 || err != 0) {
      close(fd);
      return -1;
    }
  }
  if (fcntl(fd, F_SETFL, flags) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int append_json_string(struct buffer *buf, const char *value) {
  if (buffer_append(buf, "\"", 1) != 0) {
    return -1;
  }
  for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
    unsigned char ch = *p;
    if (ch == '"' || ch == '\\') {
      char escaped[2] = {'\\', (char)ch};
      if (buffer_append(buf, escaped, sizeof(escaped)) != 0) {
        return -1;
      }
    } else if (ch < 0x20) {
      char escaped[7];
      snprintf(escaped, sizeof(escaped), "\\u%04x", ch);
      if (buffer_append(buf, escaped, 6) != 0) {
        return -1;
      }
    } else if (buffer_append(buf, &ch, 1) != 0) {
      return -1;
    }
  }
  return buffer_append(buf, "\"", 1);
}

static int build_header(struct buffer *header, int argc, char **argv) {
  if (buffer_append(header, "{\"argv\":[", 9) != 0) {
    return -1;
  }
  for (int i = 1; i < argc; i++) {
    if (i > 1 && buffer_append(header, ",", 1) != 0) {
      return -1;
    }
    if (append_json_string(header, argv[i]) != 0) {
      return -1;
    }
  }
  if (buffer_append(header, "],\"env\":{", 9) != 0) {
    return -1;
  }
  const char *env_names[] = {"ASG_HOOK_TELEMETRY_PATH", "ASG_DISABLE_HOOK_TELEMETRY"};
  int emitted = 0;
  for (size_t i = 0; i < sizeof(env_names) / sizeof(env_names[0]); i++) {
    const char *value = getenv(env_names[i]);
    if (!value) {
      continue;
    }
    if (emitted && buffer_append(header, ",", 1) != 0) {
      return -1;
    }
    if (append_json_string(header, env_names[i]) != 0 ||
        buffer_append(header, ":", 1) != 0 ||
        append_json_string(header, value) != 0) {
      return -1;
    }
    emitted = 1;
  }
  return buffer_append(header, "}}", 2);
}

static int exec_cli_direct(int argc, char **argv) {
  char *path = cli_path();
  if (!path) {
    dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
    return 1;
  }
  char **child_argv = calloc((size_t)argc + 1, sizeof(char *));
  if (!child_argv) {
    free(path);
    dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
    return 1;
  }
  child_argv[0] = path;
  for (int i = 1; i < argc; i++) {
    child_argv[i] = argv[i];
  }
  child_argv[argc] = NULL;
  execv(path, child_argv);
  free(child_argv);
  free(path);
  dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
  return 1;
}

static int fallback_cli(int argc, char **argv, const struct buffer *input) {
  char *path = cli_path();
  if (!path) {
    dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
    return 1;
  }

  int pipe_fd[2];
  if (pipe(pipe_fd) != 0) {
    free(path);
    dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fd[0]);
    close(pipe_fd[1]);
    free(path);
    dprintf(STDERR_FILENO, "asg-fast: fallback unavailable\n");
    return 1;
  }

  if (pid == 0) {
    close(pipe_fd[1]);
    if (dup2(pipe_fd[0], STDIN_FILENO) < 0) {
      _exit(127);
    }
    close(pipe_fd[0]);
    char **child_argv = calloc((size_t)argc + 1, sizeof(char *));
    if (!child_argv) {
      _exit(127);
    }
    child_argv[0] = path;
    for (int i = 1; i < argc; i++) {
      child_argv[i] = argv[i];
    }
    child_argv[argc] = NULL;
    execv(path, child_argv);
    free(child_argv);
    free(path);
    _exit(127);
  }

  close(pipe_fd[0]);
  int pipe_flags = fcntl(pipe_fd[1], F_GETFL, 0);
  if (pipe_flags >= 0) {
    (void)fcntl(pipe_fd[1], F_SETFL, pipe_flags | O_NONBLOCK);
  }
  int timeout_ms = fallback_timeout_ms();
  long long deadline_ms = now_ms() + timeout_ms;
  int status = 0;
  if (input->len && write_all_fd_until(pipe_fd[1], input->data, input->len, deadline_ms) != 0) {
    close(pipe_fd[1]);
    kill(pid, SIGTERM);
    usleep(50000);
    if (waitpid(pid, &status, WNOHANG) == 0) {
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
    }
    free(path);
    dprintf(STDERR_FILENO, "asg-fast: fallback timed out\n");
    return 124;
  }
  close(pipe_fd[1]);

  for (;;) {
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid) {
      break;
    }
    if (waited < 0 && errno != EINTR) {
      free(path);
      return 1;
    }
    if (now_ms() >= deadline_ms) {
      kill(pid, SIGTERM);
      usleep(50000);
      if (waitpid(pid, &status, WNOHANG) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
      }
      free(path);
      dprintf(STDERR_FILENO, "asg-fast: fallback timed out\n");
      return 124;
    }
    usleep(10000);
  }
  free(path);
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static int daemon_request(int argc, char **argv, const struct buffer *input) {
  if (circuit_is_open()) {
    return -1;
  }
  char *path = socket_path();
  if (!path) {
    return -1;
  }
  int fd = connect_socket(path, daemon_timeout_ms());
  free(path);
  if (fd < 0) {
    return -1;
  }

  struct buffer header = {0};
  if (build_header(&header, argc, argv) != 0 || header.len > UINT32_MAX) {
    buffer_free(&header);
    close(fd);
    return -1;
  }

  uint32_t header_len = htonl((uint32_t)header.len);
  uint64_t body_len = host_to_be64((uint64_t)input->len);
  int ok = 0;
  ok |= write_all_fd(fd, &header_len, sizeof(header_len));
  ok |= write_all_fd(fd, &body_len, sizeof(body_len));
  ok |= write_all_fd(fd, header.data, header.len);
  ok |= input->len ? write_all_fd(fd, input->data, input->len) : 0;
  buffer_free(&header);
  if (ok != 0) {
    close(fd);
    mark_circuit_unhealthy();
    return -1;
  }

  struct {
    uint32_t exit_code;
    uint32_t stderr_len;
    uint64_t stdout_len;
  } response;
  if (read_exact_fd(fd, &response, sizeof(response)) != 0) {
    close(fd);
    mark_circuit_unhealthy();
    return -1;
  }
  uint32_t exit_code = ntohl(response.exit_code);
  uint32_t stderr_len = ntohl(response.stderr_len);
  uint64_t stdout_len = be64_to_host(response.stdout_len);
  if (stream_exact_to_fd(fd, STDERR_FILENO, stderr_len) != 0 ||
      stream_exact_to_fd(fd, STDOUT_FILENO, stdout_len) != 0) {
    close(fd);
    mark_circuit_unhealthy();
    return -1;
  }
  close(fd);
  return (int)exit_code;
}

static int command_supported_by_daemon(int argc, char **argv) {
  if (argc < 2) {
    return 0;
  }
  const char *command = argv[1];
  return strcmp(command, "scan") == 0 ||
         strcmp(command, "redact") == 0 ||
         strcmp(command, "json-block") == 0 ||
         strcmp(command, "json-redact") == 0 ||
         strcmp(command, "codex-hook") == 0 ||
         strcmp(command, "cursor-hook") == 0 ||
         strcmp(command, "claude-pre") == 0 ||
         strcmp(command, "claude-post") == 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)) {
    printf("asg-fast 1.1\n");
    return 0;
  }
  if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    printf("usage: asg-fast COMMAND [ARGS...]\n");
    return 0;
  }

  if (!command_supported_by_daemon(argc, argv)) {
    return exec_cli_direct(argc, argv);
  }

  struct buffer input = {0};
  if (read_stdin_all(&input) != 0) {
    dprintf(STDERR_FILENO, "asg-fast: input unavailable\n");
    buffer_free(&input);
    return 1;
  }

  int result = daemon_request(argc, argv, &input);
  if (result < 0) {
    result = fallback_cli(argc, argv, &input);
  }
  buffer_free(&input);
  return result;
}
