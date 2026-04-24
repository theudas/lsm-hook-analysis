#include "lha_avc.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool string_present(const char *text)
{
    return text != NULL && text[0] != '\0';
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

static uint64_t absolute_diff(uint64_t a, uint64_t b)
{
    return a >= b ? a - b : b - a;
}

static bool next_perm_token(const char **cursor, char *token, size_t token_len)
{
    size_t used = 0;

    if (cursor == NULL || *cursor == NULL || token == NULL || token_len == 0) {
        return false;
    }

    while (**cursor == '|') {
        ++(*cursor);
    }

    if (**cursor == '\0') {
        token[0] = '\0';
        return false;
    }

    while (**cursor != '\0' && **cursor != '|') {
        if (used + 1 < token_len) {
            token[used++] = **cursor;
        }
        ++(*cursor);
    }

    token[used] = '\0';
    return used != 0;
}

static bool perm_list_has_token(const char *perm_list, const char *needle)
{
    const char *cursor = perm_list;
    char token[LHA_MAX_PERM_LEN];

    if (!string_present(perm_list) || !string_present(needle)) {
        return false;
    }

    while (next_perm_token(&cursor, token, sizeof(token))) {
        if (strcmp(token, needle) == 0) {
            return true;
        }
    }

    return false;
}

static bool perm_list_contains_all(const char *haystack, const char *needle)
{
    const char *cursor = needle;
    char token[LHA_MAX_PERM_LEN];

    if (!string_present(haystack) || !string_present(needle)) {
        return false;
    }

    while (next_perm_token(&cursor, token, sizeof(token))) {
        if (!perm_list_has_token(haystack, token)) {
            return false;
        }
    }

    return true;
}

static bool perm_lists_match(const char *lhs, const char *rhs)
{
    if (!string_present(lhs) || !string_present(rhs)) {
        return false;
    }

    return perm_list_contains_all(lhs, rhs) || perm_list_contains_all(rhs, lhs);
}

static bool event_has_match_keys(const struct lha_enriched_event_v1 *event)
{
    return event != NULL &&
           string_present(event->subject.scontext) &&
           string_present(event->target.tcontext) &&
           string_present(event->target.tclass) &&
           string_present(event->request.perm);
}

static bool avc_event_has_match_keys(const struct lha_avc_event_v1 *event)
{
    return event != NULL &&
           event->denied != 0 &&
           string_present(event->scontext) &&
           string_present(event->tcontext) &&
           string_present(event->tclass) &&
           string_present(event->perm);
}

static int candidate_score(const struct lha_enriched_event_v1 *event,
                           const struct lha_avc_event_v1 *avc)
{
    int score = 0;

    if (avc->tid != 0 && event->subject.tid != 0) {
        if (avc->tid != event->subject.tid) {
            return -1;
        }
        score += 4;
    }

    if (avc->pid != 0 && event->subject.pid != 0) {
        if (avc->pid != event->subject.pid) {
            return -1;
        }
        score += 2;
    }

    if (string_present(avc->comm) && string_present(event->subject.comm)) {
        if (strcmp(avc->comm, event->subject.comm) != 0) {
            return -1;
        }
        score += 1;
    }

    if (avc->permissive != 0) {
        score += 1;
    }

    return score;
}

static bool primary_fields_match(const struct lha_enriched_event_v1 *event,
                                 const struct lha_avc_event_v1 *avc,
                                 uint64_t window_ns,
                                 uint64_t *delta_ns)
{
    uint64_t delta;

    if (!event_has_match_keys(event) || !avc_event_has_match_keys(avc)) {
        return false;
    }

    if (strcmp(event->subject.scontext, avc->scontext) != 0 ||
        strcmp(event->target.tcontext, avc->tcontext) != 0 ||
        strcmp(event->target.tclass, avc->tclass) != 0 ||
        !perm_lists_match(event->request.perm, avc->perm)) {
        return false;
    }

    delta = absolute_diff(event->timestamp_ns, avc->timestamp_ns);
    if (delta > window_ns) {
        return false;
    }

    if (delta_ns != NULL) {
        *delta_ns = delta;
    }
    return true;
}

const char *lha_policy_result_kind_to_string(enum lha_policy_result_kind kind)
{
    switch (kind) {
    case LHA_POLICY_RESULT_DENY:
        return "deny";
    case LHA_POLICY_RESULT_INFERRED_ALLOW:
        return "inferred_allow";
    case LHA_POLICY_RESULT_ALLOW:
        return "allow";
    default:
        return "unknown";
    }
}

enum lha_policy_result_kind lha_correlate_avc_policy(
    const struct lha_enriched_event_v1 *event,
    const struct lha_avc_event_v1 *avc_events,
    size_t avc_count,
    const struct lha_avc_match_options *options)
{
    uint64_t window_ns = LHA_DEFAULT_AVC_WINDOW_NS;
    int best_score = -1;
    uint64_t best_delta = UINT64_MAX;
    bool ambiguous = false;
    bool matched = false;
    size_t i;

    if (options != NULL && options->window_ns != 0) {
        window_ns = options->window_ns;
    }

    if (!event_has_match_keys(event)) {
        return LHA_POLICY_RESULT_UNKNOWN;
    }

    for (i = 0; i < avc_count; ++i) {
        uint64_t delta = 0;
        int score;

        if (!primary_fields_match(event, &avc_events[i], window_ns, &delta)) {
            continue;
        }

        score = candidate_score(event, &avc_events[i]);
        if (score < 0) {
            continue;
        }

        if (!matched || score > best_score || (score == best_score && delta < best_delta)) {
            matched = true;
            ambiguous = false;
            best_score = score;
            best_delta = delta;
            continue;
        }

        if (score == best_score && delta == best_delta) {
            ambiguous = true;
        }
    }

    if (matched) {
        return ambiguous ? LHA_POLICY_RESULT_UNKNOWN : LHA_POLICY_RESULT_DENY;
    }

    return LHA_POLICY_RESULT_INFERRED_ALLOW;
}

int lha_apply_avc_policy_result(struct lha_enriched_event_v1 *event,
                                const struct lha_avc_event_v1 *avc_events,
                                size_t avc_count,
                                const struct lha_avc_match_options *options)
{
    enum lha_policy_result_kind kind;

    if (event == NULL) {
        return -1;
    }

    kind = lha_correlate_avc_policy(event, avc_events, avc_count, options);
    copy_string(event->result.policy_result, sizeof(event->result.policy_result),
                lha_policy_result_kind_to_string(kind));
    return 0;
}
