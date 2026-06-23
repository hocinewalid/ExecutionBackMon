#ifndef AMCACHE_H
#define AMCACHE_H

#include "executebackmon.h"

EvidenceNode* amcache_investigate(const char* target);
TimelineEntry* amcache_get_timeline(void);

#endif // AMCACHE_H
