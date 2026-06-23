#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void* xmalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Fatal: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void* xcalloc(size_t num, size_t size) {
    void* ptr = calloc(num, size);
    if (!ptr) {
        fprintf(stderr, "Fatal: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

char* xstrdup(const char* str) {
    if (!str) return NULL;
    char* dup = strdup(str);
    if (!dup) {
        fprintf(stderr, "Fatal: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return dup;
}

void filetime_to_systemtime(const FILETIME* ft, SYSTEMTIME* st) {
    FileTimeToSystemTime(ft, st);
}

void systemtime_to_string(const SYSTEMTIME* st, char* buffer, size_t max_len) {
    if (!st || !buffer || max_len == 0) return;
    snprintf(buffer, max_len, "%04d-%02d-%02d %02d:%02d:%02d",
             st->wYear, st->wMonth, st->wDay,
             st->wHour, st->wMinute, st->wSecond);
}

void str_to_lower(char* str) {
    if (!str) return;
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

bool ends_with(const char* str, const char* suffix) {
    if (!str || !suffix) return false;
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len) return false;
    return strcasecmp(str + str_len - suffix_len, suffix) == 0;
}

void rot13_decode(char* str) {
    if (!str) return;
    for (int i = 0; str[i]; i++) {
        if ((str[i] >= 'A' && str[i] <= 'M') || (str[i] >= 'a' && str[i] <= 'm')) {
            str[i] += 13;
        } else if ((str[i] >= 'N' && str[i] <= 'Z') || (str[i] >= 'n' && str[i] <= 'z')) {
            str[i] -= 13;
        }
    }
}

EvidenceNode* create_evidence_node(void) {
    return (EvidenceNode*)xcalloc(1, sizeof(EvidenceNode));
}

void append_evidence_node(EvidenceNode** head, EvidenceNode* node) {
    if (!head || !node) return;
    if (!*head) {
        *head = node;
        return;
    }
    EvidenceNode* current = *head;
    while (current->next) {
        current = current->next;
    }
    current->next = node;
}

void free_evidence_list(EvidenceNode* head) {
    while (head) {
        EvidenceNode* temp = head;
        head = head->next;
        free(temp);
    }
}

TimelineEntry* create_timeline_entry(void) {
    return (TimelineEntry*)xcalloc(1, sizeof(TimelineEntry));
}

void append_timeline_entry(TimelineEntry** head, TimelineEntry* node) {
    if (!head || !node) return;
    // Insert ordered by timestamp (descending or ascending)
    // For now, just append to the end.
    if (!*head) {
        *head = node;
        return;
    }
    TimelineEntry* current = *head;
    while (current->next) {
        current = current->next;
    }
    current->next = node;
}

void free_timeline_list(TimelineEntry* head) {
    while (head) {
        TimelineEntry* temp = head;
        head = head->next;
        free(temp);
    }
}
