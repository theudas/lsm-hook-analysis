#include "lha_json.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int appendf(char *buf, size_t buf_len, size_t *offset, const char *fmt, ...)
{
    va_list ap;
    int written;

    if (*offset >= buf_len) {
        return -1;
    }

    va_start(ap, fmt);
    written = vsnprintf(buf + *offset, buf_len - *offset, fmt, ap);
    va_end(ap);

    if (written < 0) {
        return -1;
    }
    if ((size_t)written >= buf_len - *offset) {
        *offset = buf_len;
        return -1;
    }

    *offset += (size_t)written;
    return 0;
}

static int append_json_string(char *buf, size_t buf_len, size_t *offset, const char *text)
{
    const unsigned char *p = (const unsigned char *)(text != NULL ? text : "");

    if (appendf(buf, buf_len, offset, "\"") != 0) {
        return -1;
    }

    while (*p != '\0') {
        switch (*p) {
        case '\\':
            if (appendf(buf, buf_len, offset, "\\\\") != 0) {
                return -1;
            }
            break;
        case '"':
            if (appendf(buf, buf_len, offset, "\\\"") != 0) {
                return -1;
            }
            break;
        case '\b':
            if (appendf(buf, buf_len, offset, "\\b") != 0) {
                return -1;
            }
            break;
        case '\f':
            if (appendf(buf, buf_len, offset, "\\f") != 0) {
                return -1;
            }
            break;
        case '\n':
            if (appendf(buf, buf_len, offset, "\\n") != 0) {
                return -1;
            }
            break;
        case '\r':
            if (appendf(buf, buf_len, offset, "\\r") != 0) {
                return -1;
            }
            break;
        case '\t':
            if (appendf(buf, buf_len, offset, "\\t") != 0) {
                return -1;
            }
            break;
        default:
            if (*p < 0x20) {
                if (appendf(buf, buf_len, offset, "\\u%04x", *p) != 0) {
                    return -1;
                }
            } else {
                if (appendf(buf, buf_len, offset, "%c", *p) != 0) {
                    return -1;
                }
            }
            break;
        }
        ++p;
    }

    return appendf(buf, buf_len, offset, "\"");
}

int lha_event_to_json(const struct lha_enriched_event_v1 *event, char *buf, size_t buf_len)
{
    size_t offset = 0;

    if (event == NULL || buf == NULL || buf_len == 0) {
        return -1;
    }

    buf[0] = '\0';

    if (appendf(buf, buf_len, &offset, "{\n") != 0 ||
        appendf(buf, buf_len, &offset, "  \"hook\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->hook) != 0 ||
        appendf(buf, buf_len, &offset, ",\n  \"hook_signature\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->hook_signature) != 0 ||
        appendf(buf, buf_len, &offset, ",\n  \"timestamp_ns\": %llu,\n",
                (unsigned long long)event->timestamp_ns) != 0 ||
        appendf(buf, buf_len, &offset, "  \"subject\": {\n") != 0 ||
        appendf(buf, buf_len, &offset, "    \"pid\": %u,\n", event->subject.pid) != 0 ||
        appendf(buf, buf_len, &offset, "    \"tid\": %u,\n", event->subject.tid) != 0 ||
        appendf(buf, buf_len, &offset, "    \"scontext\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->subject.scontext) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"comm\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->subject.comm) != 0 ||
        appendf(buf, buf_len, &offset, "\n  },\n") != 0 ||
        appendf(buf, buf_len, &offset, "  \"request\": {\n") != 0 ||
        appendf(buf, buf_len, &offset, "    \"mask_raw\": %d,\n", event->request.mask_raw) != 0 ||
        appendf(buf, buf_len, &offset, "    \"obj_type\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->request.obj_type) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"perm\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->request.perm) != 0 ||
        appendf(buf, buf_len, &offset, "\n  },\n") != 0 ||
        appendf(buf, buf_len, &offset, "  \"target\": {\n") != 0 ||
        appendf(buf, buf_len, &offset, "    \"dev\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->target.dev) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"ino\": %llu,\n",
                (unsigned long long)event->target.ino) != 0 ||
        appendf(buf, buf_len, &offset, "    \"type\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->target.type) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"path\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->target.path) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"tclass\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->target.tclass) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"tcontext\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->target.tcontext) != 0 ||
        appendf(buf, buf_len, &offset, "\n  },\n") != 0 ||
        appendf(buf, buf_len, &offset, "  \"result\": {\n") != 0 ||
        appendf(buf, buf_len, &offset, "    \"ret\": %d,\n", event->result.ret) != 0 ||
        appendf(buf, buf_len, &offset, "    \"runtime_result\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->result.runtime_result) != 0 ||
        appendf(buf, buf_len, &offset, ",\n    \"policy_result\": ") != 0 ||
        append_json_string(buf, buf_len, &offset, event->result.policy_result) != 0 ||
        appendf(buf, buf_len, &offset, "\n  }\n}\n") != 0) {
        return -1;
    }

    return (int)offset;
}

