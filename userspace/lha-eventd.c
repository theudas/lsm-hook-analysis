#define _POSIX_C_SOURCE 200809L

#include "../include/uapi/lha_event_stream.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LHA_DEFAULT_DEVICE_PATH "/dev/lha_centos9_event_stream"
#define LHA_DEFAULT_OUTPUT_DIR "/var/log/lha"
#define LHA_DEFAULT_FLUSH_INTERVAL_MS 1000
#define LHA_DEFAULT_FSYNC_INTERVAL_MS 5000
#define LHA_DEFAULT_MAX_BATCH_RECORDS 128
#define LHA_DEFAULT_DIR_MODE 0750
#define LHA_DEFAULT_FILE_MODE 0640
#define LHA_JSON_BUF_LEN 8192
#define LHA_PATH_BUF_LEN 1024

struct lha_eventd_config {
	char device_path[LHA_PATH_BUF_LEN];
	char output_dir[LHA_PATH_BUF_LEN];
	int flush_interval_ms;
	int fsync_interval_ms;
	size_t max_batch_records;
	mode_t dir_mode;
	mode_t file_mode;
};

struct lha_eventd_log_state {
	FILE *fp;
	int fd;
	char current_day[16];
	char current_path[LHA_PATH_BUF_LEN];
	struct timespec last_flush;
	struct timespec last_fsync;
};

static void lha_copy_string(char *dst, size_t dst_len, const char *src)
{
	if (dst_len == 0)
		return;

	if (!src) {
		dst[0] = '\0';
		return;
	}

	strncpy(dst, src, dst_len - 1);
	dst[dst_len - 1] = '\0';
}

static void lha_set_default_config(struct lha_eventd_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	lha_copy_string(cfg->device_path, sizeof(cfg->device_path),
			LHA_DEFAULT_DEVICE_PATH);
	lha_copy_string(cfg->output_dir, sizeof(cfg->output_dir),
			LHA_DEFAULT_OUTPUT_DIR);
	cfg->flush_interval_ms = LHA_DEFAULT_FLUSH_INTERVAL_MS;
	cfg->fsync_interval_ms = LHA_DEFAULT_FSYNC_INTERVAL_MS;
	cfg->max_batch_records = LHA_DEFAULT_MAX_BATCH_RECORDS;
	cfg->dir_mode = LHA_DEFAULT_DIR_MODE;
	cfg->file_mode = LHA_DEFAULT_FILE_MODE;
}

static void lha_trim(char *text)
{
	char *start = text;
	char *end;

	while (*start == ' ' || *start == '\t')
		++start;

	if (start != text)
		memmove(text, start, strlen(start) + 1);

	end = text + strlen(text);
	while (end > text && (end[-1] == '\n' || end[-1] == '\r' ||
			       end[-1] == ' ' || end[-1] == '\t')) {
		--end;
	}
	*end = '\0';
}

static int lha_parse_int(const char *value, int *out)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0')
		return -1;
	if (parsed < 0 || parsed > INT32_MAX)
		return -1;

	*out = (int)parsed;
	return 0;
}

static int lha_parse_size(const char *value, size_t *out)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0')
		return -1;

	*out = (size_t)parsed;
	return 0;
}

static int lha_parse_mode(const char *value, mode_t *out)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 8);
	if (errno != 0 || end == value || *end != '\0')
		return -1;

	*out = (mode_t)parsed;
	return 0;
}

static int lha_apply_config_entry(struct lha_eventd_config *cfg,
				  const char *key,
				  const char *value)
{
	if (strcmp(key, "device_path") == 0) {
		lha_copy_string(cfg->device_path, sizeof(cfg->device_path), value);
		return 0;
	}
	if (strcmp(key, "output_dir") == 0) {
		lha_copy_string(cfg->output_dir, sizeof(cfg->output_dir), value);
		return 0;
	}
	if (strcmp(key, "flush_interval_ms") == 0)
		return lha_parse_int(value, &cfg->flush_interval_ms);
	if (strcmp(key, "fsync_interval_ms") == 0)
		return lha_parse_int(value, &cfg->fsync_interval_ms);
	if (strcmp(key, "max_batch_records") == 0)
		return lha_parse_size(value, &cfg->max_batch_records);
	if (strcmp(key, "dir_mode") == 0)
		return lha_parse_mode(value, &cfg->dir_mode);
	if (strcmp(key, "file_mode") == 0)
		return lha_parse_mode(value, &cfg->file_mode);

	return -1;
}

static int lha_load_config_file(const char *path, struct lha_eventd_config *cfg)
{
	FILE *fp;
	char line[2048];
	unsigned int lineno = 0;

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		perror("fopen config");
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *eq;
		char *key;
		char *value;

		++lineno;
		lha_trim(line);
		if (line[0] == '\0' || line[0] == '#')
			continue;

		eq = strchr(line, '=');
		if (!eq) {
			fprintf(stderr, "config parse error at %s:%u\n", path, lineno);
			fclose(fp);
			return -1;
		}

		*eq = '\0';
		key = line;
		value = eq + 1;
		lha_trim(key);
		lha_trim(value);

		if (lha_apply_config_entry(cfg, key, value) != 0) {
			fprintf(stderr, "invalid config value at %s:%u\n", path, lineno);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

static int lha_apply_cli_arg(struct lha_eventd_config *cfg,
			     const char *arg)
{
	char *dup;
	char *eq;
	int rc;

	dup = strdup(arg);
	if (!dup)
		return -1;

	eq = strchr(dup, '=');
	if (!eq) {
		free(dup);
		return -1;
	}

	*eq = '\0';
	rc = lha_apply_config_entry(cfg, dup, eq + 1);
	free(dup);
	return rc;
}

static long long lha_timespec_diff_ms(const struct timespec *now,
				      const struct timespec *prev)
{
	long long sec_diff = (long long)now->tv_sec - (long long)prev->tv_sec;
	long long nsec_diff = (long long)now->tv_nsec - (long long)prev->tv_nsec;

	return sec_diff * 1000LL + nsec_diff / 1000000LL;
}

static int lha_ensure_dir(const char *path, mode_t mode)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s exists but is not a directory\n", path);
			return -1;
		}
		return 0;
	}

	if (errno != ENOENT) {
		perror("stat output_dir");
		return -1;
	}

	if (mkdir(path, mode) != 0) {
		perror("mkdir output_dir");
		return -1;
	}

	return 0;
}

static int lha_ns_to_day_string(uint64_t timestamp_ns,
				char *day_buf,
				size_t day_buf_len)
{
	time_t secs = (time_t)(timestamp_ns / 1000000000ULL);
	struct tm tm_result;

	if (!localtime_r(&secs, &tm_result))
		return -1;

	if (strftime(day_buf, day_buf_len, "%Y-%m-%d", &tm_result) == 0)
		return -1;

	return 0;
}

static int lha_open_log_file(struct lha_eventd_log_state *state,
			     const struct lha_eventd_config *cfg,
			     const char *day)
{
	int fd;
	char path[LHA_PATH_BUF_LEN];
	FILE *fp;

	if (snprintf(path, sizeof(path), "%s/%s.log", cfg->output_dir, day) >=
	    (int)sizeof(path)) {
		fprintf(stderr, "log path too long for day %s\n", day);
		return -1;
	}

	fd = open(path, O_CREAT | O_APPEND | O_WRONLY, cfg->file_mode);
	if (fd < 0) {
		perror("open log file");
		return -1;
	}

	if (fchmod(fd, cfg->file_mode) != 0)
		perror("fchmod log file");

	fp = fdopen(fd, "a");
	if (!fp) {
		perror("fdopen log file");
		close(fd);
		return -1;
	}

	if (state->fp)
		fclose(state->fp);

	state->fp = fp;
	state->fd = fd;
	lha_copy_string(state->current_day, sizeof(state->current_day), day);
	lha_copy_string(state->current_path, sizeof(state->current_path), path);
	clock_gettime(CLOCK_REALTIME, &state->last_flush);
	state->last_fsync = state->last_flush;
	return 0;
}

static int lha_ensure_log_target(struct lha_eventd_log_state *state,
				 const struct lha_eventd_config *cfg,
				 uint64_t timestamp_ns)
{
	char day[16];

	if (lha_ns_to_day_string(timestamp_ns, day, sizeof(day)) != 0) {
		fprintf(stderr, "failed to convert timestamp to day\n");
		return -1;
	}

	if (state->fp && strcmp(state->current_day, day) == 0)
		return 0;

	return lha_open_log_file(state, cfg, day);
}

static int lha_append_json_escaped(char *buf, size_t buf_len, size_t *off,
				   const char *text)
{
	const unsigned char *p = (const unsigned char *)(text ? text : "");
	int n;

	if (*off >= buf_len)
		return -1;

	n = snprintf(buf + *off, buf_len - *off, "\"");
	if (n < 0 || (size_t)n >= buf_len - *off)
		return -1;
	*off += (size_t)n;

	while (*p != '\0') {
		switch (*p) {
		case '\\':
			n = snprintf(buf + *off, buf_len - *off, "\\\\");
			break;
		case '"':
			n = snprintf(buf + *off, buf_len - *off, "\\\"");
			break;
		case '\b':
			n = snprintf(buf + *off, buf_len - *off, "\\b");
			break;
		case '\f':
			n = snprintf(buf + *off, buf_len - *off, "\\f");
			break;
		case '\n':
			n = snprintf(buf + *off, buf_len - *off, "\\n");
			break;
		case '\r':
			n = snprintf(buf + *off, buf_len - *off, "\\r");
			break;
		case '\t':
			n = snprintf(buf + *off, buf_len - *off, "\\t");
			break;
		default:
			if (*p < 0x20)
				n = snprintf(buf + *off, buf_len - *off,
					     "\\u%04x", *p);
			else
				n = snprintf(buf + *off, buf_len - *off, "%c", *p);
			break;
		}
		if (n < 0 || (size_t)n >= buf_len - *off)
			return -1;
		*off += (size_t)n;
		++p;
	}

	n = snprintf(buf + *off, buf_len - *off, "\"");
	if (n < 0 || (size_t)n >= buf_len - *off)
		return -1;
	*off += (size_t)n;
	return 0;
}

static int lha_format_ndjson(const struct lha_event_payload_v1 *event,
			     char *buf,
			     size_t buf_len)
{
	size_t off = 0;
	int n;

#define APPENDF(...)                                                         \
	do {                                                                \
		n = snprintf(buf + off, buf_len - off, __VA_ARGS__);        \
		if (n < 0 || (size_t)n >= buf_len - off)                   \
			return -1;                                         \
		off += (size_t)n;                                         \
	} while (0)

	APPENDF("{\"hook\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->hook) != 0)
		return -1;
	APPENDF(",\"hook_signature\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->hook_signature) != 0)
		return -1;
	APPENDF(",\"timestamp_ns\":%llu,\"subject\":{\"pid\":%u,\"tid\":%u,\"scontext\":",
		(unsigned long long)event->timestamp_ns,
		event->subject.pid, event->subject.tid);
	if (lha_append_json_escaped(buf, buf_len, &off, event->subject.scontext) != 0)
		return -1;
	APPENDF(",\"comm\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->subject.comm) != 0)
		return -1;
	APPENDF("},\"request\":{\"mask_raw\":%d,\"obj_type\":",
		event->request.mask_raw);
	if (lha_append_json_escaped(buf, buf_len, &off, event->request.obj_type) != 0)
		return -1;
	APPENDF(",\"perm\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->request.perm) != 0)
		return -1;
	APPENDF("},\"target\":{\"dev\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->target.dev) != 0)
		return -1;
	APPENDF(",\"ino\":%llu,\"type\":",
		(unsigned long long)event->target.ino);
	if (lha_append_json_escaped(buf, buf_len, &off, event->target.type) != 0)
		return -1;
	APPENDF(",\"path\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->target.path) != 0)
		return -1;
	APPENDF(",\"tclass\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->target.tclass) != 0)
		return -1;
	APPENDF(",\"tcontext\":");
	if (lha_append_json_escaped(buf, buf_len, &off, event->target.tcontext) != 0)
		return -1;
	APPENDF("},\"result\":{\"ret\":%d,\"runtime_result\":",
		event->result.ret);
	if (lha_append_json_escaped(buf, buf_len, &off,
				    event->result.runtime_result) != 0)
		return -1;
	APPENDF(",\"policy_result\":");
	if (lha_append_json_escaped(buf, buf_len, &off,
				    event->result.policy_result) != 0)
		return -1;
	APPENDF("}}\n");

#undef APPENDF

	return 0;
}

static int lha_validate_frame(const struct lha_event_frame_v1 *frame)
{
	if (frame->hdr.magic != LHA_EVENT_STREAM_MAGIC)
		return -1;
	if (frame->hdr.abi_version != LHA_EVENT_STREAM_ABI_V1)
		return -1;
	if (frame->hdr.frame_type != LHA_EVENT_FRAME_DATA)
		return -1;
	if (frame->hdr.header_len != sizeof(frame->hdr))
		return -1;
	if (frame->hdr.payload_version != LHA_EVENT_STREAM_PAYLOAD_V1)
		return -1;
	if (frame->hdr.payload_len != sizeof(frame->payload))
		return -1;
	if (frame->payload.version != LHA_EVENT_STREAM_PAYLOAD_V1)
		return -1;

	return 0;
}

static int lha_maybe_flush(struct lha_eventd_log_state *state,
			   const struct lha_eventd_config *cfg)
{
	struct timespec now;

	if (!state->fp)
		return 0;

	if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		perror("clock_gettime");
		return -1;
	}

	if (cfg->flush_interval_ms > 0 &&
	    lha_timespec_diff_ms(&now, &state->last_flush) >=
		    cfg->flush_interval_ms) {
		if (fflush(state->fp) != 0) {
			perror("fflush");
			return -1;
		}
		state->last_flush = now;
	}

	if (cfg->fsync_interval_ms > 0 &&
	    lha_timespec_diff_ms(&now, &state->last_fsync) >=
		    cfg->fsync_interval_ms) {
		if (fflush(state->fp) != 0) {
			perror("fflush");
			return -1;
		}
		if (fsync(state->fd) != 0) {
			perror("fsync");
			return -1;
		}
		state->last_flush = now;
		state->last_fsync = now;
	}

	return 0;
}

static int lha_process_frames(const struct lha_event_frame_v1 *frames,
			      size_t frame_count,
			      const struct lha_eventd_config *cfg,
			      struct lha_eventd_log_state *state,
			      uint64_t *last_seq,
			      bool *have_last_seq)
{
	size_t i;

	for (i = 0; i < frame_count; ++i) {
		char json[LHA_JSON_BUF_LEN];

		if (lha_validate_frame(&frames[i]) != 0) {
			fprintf(stderr, "received invalid frame from kernel\n");
			return -1;
		}

		if (*have_last_seq && frames[i].hdr.seq != *last_seq + 1) {
			if (frames[i].hdr.seq <= *last_seq) {
				fprintf(stderr,
					"event sequence reset detected: prev=%llu current=%llu\n",
					(unsigned long long)*last_seq,
					(unsigned long long)frames[i].hdr.seq);
			} else {
				fprintf(stderr,
					"event sequence gap detected: prev=%llu current=%llu lost=%llu\n",
					(unsigned long long)*last_seq,
					(unsigned long long)frames[i].hdr.seq,
					(unsigned long long)(frames[i].hdr.seq - *last_seq - 1));
			}
		}
		*last_seq = frames[i].hdr.seq;
		*have_last_seq = true;

		if (lha_ensure_log_target(state, cfg,
					  frames[i].payload.timestamp_ns) != 0)
			return -1;

		if (lha_format_ndjson(&frames[i].payload, json, sizeof(json)) != 0) {
			fprintf(stderr, "failed to format event as NDJSON\n");
			return -1;
		}

		if (fputs(json, state->fp) == EOF) {
			perror("fputs log");
			return -1;
		}
	}

	return lha_maybe_flush(state, cfg);
}

static void lha_close_log_state(struct lha_eventd_log_state *state)
{
	if (!state->fp)
		return;

	fflush(state->fp);
	fsync(state->fd);
	fclose(state->fp);
	state->fp = NULL;
	state->fd = -1;
	state->current_day[0] = '\0';
	state->current_path[0] = '\0';
}

static void lha_print_usage(FILE *stream, const char *prog)
{
	fprintf(stream,
		"Usage: %s [--config PATH] [key=value ...]\n"
		"Supported keys: device_path output_dir flush_interval_ms "
		"fsync_interval_ms max_batch_records dir_mode file_mode\n",
		prog);
}

int main(int argc, char **argv)
{
	struct lha_eventd_config cfg;
	struct lha_eventd_log_state log_state;
	struct lha_event_frame_v1 *frames = NULL;
	struct pollfd pfd;
	const char *config_path = "/etc/lha-eventd.conf";
	uint64_t last_seq = 0;
	bool have_last_seq = false;
	int fd = -1;
	int i;

	lha_set_default_config(&cfg);
	memset(&log_state, 0, sizeof(log_state));
	log_state.fd = -1;

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--config") == 0) {
			if (i + 1 >= argc) {
				lha_print_usage(stderr, argv[0]);
				return 1;
			}
			config_path = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--help") == 0) {
			lha_print_usage(stdout, argv[0]);
			return 0;
		}
	}

	if (lha_load_config_file(config_path, &cfg) != 0)
		return 1;

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--config") == 0) {
			++i;
			continue;
		}
		if (strcmp(argv[i], "--help") == 0)
			continue;
		if (lha_apply_cli_arg(&cfg, argv[i]) != 0) {
			fprintf(stderr, "invalid argument: %s\n", argv[i]);
			lha_print_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (cfg.max_batch_records == 0)
		cfg.max_batch_records = LHA_DEFAULT_MAX_BATCH_RECORDS;

	if (lha_ensure_dir(cfg.output_dir, cfg.dir_mode) != 0)
		return 1;

	frames = calloc(cfg.max_batch_records, sizeof(*frames));
	if (!frames) {
		perror("calloc frames");
		return 1;
	}

	for (;;) {
		fd = open(cfg.device_path, O_RDONLY);
		if (fd < 0) {
			perror("open device");
			sleep(1);
			continue;
		}

		pfd.fd = fd;
		pfd.events = POLLIN;

		for (;;) {
			ssize_t bytes;
			size_t frame_count;

			if (poll(&pfd, 1, -1) < 0) {
				if (errno == EINTR)
					continue;
				perror("poll");
				break;
			}

			if (pfd.revents & (POLLERR | POLLHUP)) {
				fprintf(stderr, "device poll returned error/hup\n");
				break;
			}
			if (!(pfd.revents & POLLIN))
				continue;

			bytes = read(fd, frames,
				     cfg.max_batch_records * sizeof(*frames));
			if (bytes < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					continue;
				perror("read device");
				break;
			}
			if (bytes == 0) {
				fprintf(stderr, "device returned EOF\n");
				break;
			}
			if ((size_t)bytes % sizeof(*frames) != 0) {
				fprintf(stderr, "device returned partial frame set\n");
				break;
			}

			frame_count = (size_t)bytes / sizeof(*frames);
			if (lha_process_frames(frames, frame_count, &cfg,
					      &log_state, &last_seq,
					      &have_last_seq) != 0) {
				close(fd);
				lha_close_log_state(&log_state);
				free(frames);
				return 1;
			}
		}

		close(fd);
		fd = -1;
		have_last_seq = false;
		sleep(1);
	}

	free(frames);
	lha_close_log_state(&log_state);
	return 0;
}
