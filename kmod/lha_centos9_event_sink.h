#ifndef LHA_CENTOS9_EVENT_SINK_H
#define LHA_CENTOS9_EVENT_SINK_H

#include "lha_centos9_resolver.h"

int lha_centos9_submit_event(const struct lha_enriched_event_v1 *event);

#endif
