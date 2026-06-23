#ifndef EVENTLOG_H
#define EVENTLOG_H

#include "executebackmon.h"

EvidenceNode* eventlog_investigate(const char* target);
TimelineEntry* eventlog_get_timeline(void);

#endif // EVENTLOG_H
