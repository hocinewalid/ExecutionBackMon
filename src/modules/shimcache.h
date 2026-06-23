#ifndef SHIMCACHE_H
#define SHIMCACHE_H

#include "executebackmon.h"

EvidenceNode* shimcache_investigate(const char* target);
TimelineEntry* shimcache_get_timeline(void);

#endif // SHIMCACHE_H
