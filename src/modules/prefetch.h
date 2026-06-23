#ifndef PREFETCH_H
#define PREFETCH_H

#include "executebackmon.h"

EvidenceNode* prefetch_investigate(const char* target);
TimelineEntry* prefetch_get_timeline(void);

#endif // PREFETCH_H
