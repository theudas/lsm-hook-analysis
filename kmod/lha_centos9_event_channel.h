#ifndef LHA_CENTOS9_EVENT_CHANNEL_H
#define LHA_CENTOS9_EVENT_CHANNEL_H

#include "lha_centos9_resolver.h"

struct module;

struct lha_event_channel_ops {
	struct module *owner;
	int (*submit)(const struct lha_enriched_event_v1 *event);
};

int lha_centos9_submit_event(const struct lha_enriched_event_v1 *event);
int lha_centos9_register_event_channel(const struct lha_event_channel_ops *ops);
int lha_centos9_unregister_event_channel(const struct lha_event_channel_ops *ops);

#endif
