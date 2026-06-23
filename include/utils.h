#ifndef UTILS_H
#define UTILS_H

#include "executebackmon.h"

// Memory management
void* xmalloc(size_t size);
void* xcalloc(size_t num, size_t size);
char* xstrdup(const char* str);

// Time conversions
void filetime_to_systemtime(const FILETIME* ft, SYSTEMTIME* st);
void systemtime_to_string(const SYSTEMTIME* st, char* buffer, size_t max_len);

// String utilities
void str_to_lower(char* str);
bool ends_with(const char* str, const char* suffix);

// ROT13 decode (for UserAssist)
void rot13_decode(char* str);

// Linked list helpers
EvidenceNode* create_evidence_node(void);
void append_evidence_node(EvidenceNode** head, EvidenceNode* node);
void free_evidence_list(EvidenceNode* head);

TimelineEntry* create_timeline_entry(void);
void append_timeline_entry(TimelineEntry** head, TimelineEntry* node);
void free_timeline_list(TimelineEntry* head);

#endif // UTILS_H
