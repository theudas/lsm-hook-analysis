#ifndef LHA_AVC_H
#define LHA_AVC_H

#include <stddef.h>
#include <stdint.h>

#include "lha_types.h"

#define LHA_DEFAULT_AVC_WINDOW_NS 50000000ull

enum lha_policy_result_kind {
    LHA_POLICY_RESULT_UNKNOWN = 0,
    LHA_POLICY_RESULT_DENY = 1,
    LHA_POLICY_RESULT_INFERRED_ALLOW = 2,
    LHA_POLICY_RESULT_ALLOW = 3,
};

struct lha_avc_event_v1 {
    uint64_t timestamp_ns;
    char scontext[LHA_MAX_CONTEXT_LEN];
    char tcontext[LHA_MAX_CONTEXT_LEN];
    char tclass[LHA_MAX_TYPE_LEN];
    char perm[LHA_MAX_PERM_LEN];
    uint32_t pid;
    uint32_t tid;
    char comm[LHA_MAX_COMM_LEN];
    uint8_t permissive;
    uint8_t denied;
    uint8_t reserved[2];
};

struct lha_avc_match_options {
    uint64_t window_ns;
};

const char *lha_policy_result_kind_to_string(enum lha_policy_result_kind kind);

enum lha_policy_result_kind lha_correlate_avc_policy(
    const struct lha_enriched_event_v1 *event,
    const struct lha_avc_event_v1 *avc_events,
    size_t avc_count,
    const struct lha_avc_match_options *options);

int lha_apply_avc_policy_result(struct lha_enriched_event_v1 *event,
                                const struct lha_avc_event_v1 *avc_events,
                                size_t avc_count,
                                const struct lha_avc_match_options *options);

#endif
