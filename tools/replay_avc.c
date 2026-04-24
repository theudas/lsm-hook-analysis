#include "lha_avc.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct replay_config {
    struct lha_enriched_event_v1 event;
    struct lha_avc_event_v1 avc;
    struct lha_avc_match_options options;
    bool use_avc;
};

static void print_usage(FILE *stream, const char *prog)
{
    fprintf(stream,
            "Usage: %s [options]\n"
            "  --event-ts NS\n"
            "  --event-scontext CTX\n"
            "  --event-tcontext CTX\n"
            "  --event-tclass CLASS\n"
            "  --event-perm PERM\n"
            "  --event-pid PID\n"
            "  --event-tid TID\n"
            "  --event-comm COMM\n"
            "  --avc-ts NS\n"
            "  --avc-scontext CTX\n"
            "  --avc-tcontext CTX\n"
            "  --avc-tclass CLASS\n"
            "  --avc-perm PERM\n"
            "  --avc-pid PID\n"
            "  --avc-tid TID\n"
            "  --avc-comm COMM\n"
            "  --avc-denied 0|1\n"
            "  --avc-permissive 0|1\n"
            "  --window-ns NS\n"
            "  --no-avc\n"
            "  --help\n"
            "\n"
            "If no arguments are provided, a built-in sample is used.\n",
            prog);
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || out == NULL || text[0] == '\0') {
        return -1;
    }

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }

    *out = (uint64_t)value;
    return 0;
}

static int parse_u32(const char *text, uint32_t *out)
{
    uint64_t value = 0;

    if (parse_u64(text, &value) != 0 || value > UINT32_MAX) {
        return -1;
    }

    *out = (uint32_t)value;
    return 0;
}

static int parse_u8(const char *text, uint8_t *out)
{
    uint64_t value = 0;

    if (parse_u64(text, &value) != 0 || value > UINT8_MAX) {
        return -1;
    }

    *out = (uint8_t)value;
    return 0;
}

static void copy_string(char *dst, size_t dst_len, const char *src)
{
    if (dst_len == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_len, "%s", src);
}

static void init_sample(struct replay_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->use_avc = true;
    cfg->options.window_ns = LHA_DEFAULT_AVC_WINDOW_NS;

    cfg->event.timestamp_ns = 1000000000ull;
    cfg->event.subject.pid = 7059u;
    cfg->event.subject.tid = 7059u;
    copy_string(cfg->event.subject.comm, sizeof(cfg->event.subject.comm), "runcon");
    copy_string(cfg->event.subject.scontext, sizeof(cfg->event.subject.scontext),
                "system_u:system_r:httpd_t:s0");
    copy_string(cfg->event.target.tcontext, sizeof(cfg->event.target.tcontext),
                "system_u:object_r:bin_t:s0");
    copy_string(cfg->event.target.tclass, sizeof(cfg->event.target.tclass), "file");
    copy_string(cfg->event.request.perm, sizeof(cfg->event.request.perm), "entrypoint");

    cfg->avc.timestamp_ns = 1000001000ull;
    cfg->avc.pid = cfg->event.subject.pid;
    cfg->avc.tid = cfg->event.subject.tid;
    copy_string(cfg->avc.comm, sizeof(cfg->avc.comm), cfg->event.subject.comm);
    copy_string(cfg->avc.scontext, sizeof(cfg->avc.scontext), cfg->event.subject.scontext);
    copy_string(cfg->avc.tcontext, sizeof(cfg->avc.tcontext), cfg->event.target.tcontext);
    copy_string(cfg->avc.tclass, sizeof(cfg->avc.tclass), cfg->event.target.tclass);
    copy_string(cfg->avc.perm, sizeof(cfg->avc.perm), cfg->event.request.perm);
    cfg->avc.denied = 1u;
}

static int require_value(int argc, char **argv, int *index)
{
    if (*index + 1 >= argc) {
        fprintf(stderr, "missing value for %s\n", argv[*index]);
        return -1;
    }

    ++(*index);
    return 0;
}

static int parse_args(struct replay_config *cfg, int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            return 1;
        }
        if (strcmp(arg, "--no-avc") == 0) {
            cfg->use_avc = false;
            continue;
        }

        if (require_value(argc, argv, &i) != 0) {
            return -1;
        }

        if (strcmp(arg, "--event-ts") == 0) {
            if (parse_u64(argv[i], &cfg->event.timestamp_ns) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--event-scontext") == 0) {
            copy_string(cfg->event.subject.scontext, sizeof(cfg->event.subject.scontext), argv[i]);
        } else if (strcmp(arg, "--event-tcontext") == 0) {
            copy_string(cfg->event.target.tcontext, sizeof(cfg->event.target.tcontext), argv[i]);
        } else if (strcmp(arg, "--event-tclass") == 0) {
            copy_string(cfg->event.target.tclass, sizeof(cfg->event.target.tclass), argv[i]);
        } else if (strcmp(arg, "--event-perm") == 0) {
            copy_string(cfg->event.request.perm, sizeof(cfg->event.request.perm), argv[i]);
        } else if (strcmp(arg, "--event-pid") == 0) {
            if (parse_u32(argv[i], &cfg->event.subject.pid) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--event-tid") == 0) {
            if (parse_u32(argv[i], &cfg->event.subject.tid) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--event-comm") == 0) {
            copy_string(cfg->event.subject.comm, sizeof(cfg->event.subject.comm), argv[i]);
        } else if (strcmp(arg, "--avc-ts") == 0) {
            if (parse_u64(argv[i], &cfg->avc.timestamp_ns) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--avc-scontext") == 0) {
            copy_string(cfg->avc.scontext, sizeof(cfg->avc.scontext), argv[i]);
        } else if (strcmp(arg, "--avc-tcontext") == 0) {
            copy_string(cfg->avc.tcontext, sizeof(cfg->avc.tcontext), argv[i]);
        } else if (strcmp(arg, "--avc-tclass") == 0) {
            copy_string(cfg->avc.tclass, sizeof(cfg->avc.tclass), argv[i]);
        } else if (strcmp(arg, "--avc-perm") == 0) {
            copy_string(cfg->avc.perm, sizeof(cfg->avc.perm), argv[i]);
        } else if (strcmp(arg, "--avc-pid") == 0) {
            if (parse_u32(argv[i], &cfg->avc.pid) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--avc-tid") == 0) {
            if (parse_u32(argv[i], &cfg->avc.tid) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--avc-comm") == 0) {
            copy_string(cfg->avc.comm, sizeof(cfg->avc.comm), argv[i]);
        } else if (strcmp(arg, "--avc-denied") == 0) {
            if (parse_u8(argv[i], &cfg->avc.denied) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--avc-permissive") == 0) {
            if (parse_u8(argv[i], &cfg->avc.permissive) != 0) {
                return -1;
            }
        } else if (strcmp(arg, "--window-ns") == 0) {
            if (parse_u64(argv[i], &cfg->options.window_ns) != 0) {
                return -1;
            }
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            return -1;
        }
    }

    return 0;
}

static void print_summary(const struct replay_config *cfg)
{
    printf("event: ts=%" PRIu64 " pid=%u tid=%u comm=%s perm=%s scontext=%s tcontext=%s tclass=%s\n",
           cfg->event.timestamp_ns,
           cfg->event.subject.pid,
           cfg->event.subject.tid,
           cfg->event.subject.comm,
           cfg->event.request.perm,
           cfg->event.subject.scontext,
           cfg->event.target.tcontext,
           cfg->event.target.tclass);

    if (!cfg->use_avc) {
        printf("avc: disabled\n");
        return;
    }

    printf("avc:   ts=%" PRIu64 " pid=%u tid=%u comm=%s perm=%s denied=%u permissive=%u scontext=%s tcontext=%s tclass=%s\n",
           cfg->avc.timestamp_ns,
           cfg->avc.pid,
           cfg->avc.tid,
           cfg->avc.comm,
           cfg->avc.perm,
           (unsigned int)cfg->avc.denied,
           (unsigned int)cfg->avc.permissive,
           cfg->avc.scontext,
           cfg->avc.tcontext,
           cfg->avc.tclass);
}

int main(int argc, char **argv)
{
    struct replay_config cfg;
    const struct lha_avc_event_v1 *avc_events = NULL;
    size_t avc_count = 0;
    int parse_rc;

    init_sample(&cfg);
    parse_rc = parse_args(&cfg, argc, argv);
    if (parse_rc == 1) {
        print_usage(stdout, argv[0]);
        return 0;
    }
    if (parse_rc != 0) {
        print_usage(stderr, argv[0]);
        return 1;
    }

    if (cfg.use_avc) {
        avc_events = &cfg.avc;
        avc_count = 1;
    }

    print_summary(&cfg);
    if (lha_apply_avc_policy_result(&cfg.event, avc_events, avc_count, &cfg.options) != 0) {
        fprintf(stderr, "lha_apply_avc_policy_result failed\n");
        return 1;
    }

    printf("policy_result=%s\n", cfg.event.result.policy_result);
    return 0;
}
