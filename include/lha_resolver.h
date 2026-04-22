#ifndef LHA_RESOLVER_H
#define LHA_RESOLVER_H

#include "lha_kernel_api.h"
#include "lha_types.h"

int lha_resolve_event(const struct lha_kernel_ops *ops,
                      const struct lha_capture_event_v1 *event,
                      struct lha_enriched_event_v1 *out);

#endif
