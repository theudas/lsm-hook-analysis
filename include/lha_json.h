#ifndef LHA_JSON_H
#define LHA_JSON_H

#include <stddef.h>

#include "lha_types.h"

int lha_event_to_json(const struct lha_enriched_event_v1 *event, char *buf, size_t buf_len);

#endif

