#include "timeline.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_timeline(void) {
    TimelineEntry* head = NULL;
    
    // Collect from modules
    TimelineEntry* bam = bam_get_timeline();
    TimelineEntry* ua = userassist_get_timeline();
    TimelineEntry* shim = shimcache_get_timeline();
    TimelineEntry* ev = eventlog_get_timeline();
    TimelineEntry* pf = prefetch_get_timeline();
    TimelineEntry* am = amcache_get_timeline();

    // Very naive merge: just append them together
    // A proper timeline would sort them by timestamp.
    append_timeline_entry(&head, bam);
    append_timeline_entry(&head, ua);
    append_timeline_entry(&head, shim);
    append_timeline_entry(&head, ev);
    append_timeline_entry(&head, pf);
    append_timeline_entry(&head, am);

    // Print
    printf("--- Execution Timeline ---\n");
    TimelineEntry* cur = head;
    while(cur) {
        char time_str[64] = "Unknown Time";
        if (cur->timestamp.wYear != 0) {
            systemtime_to_string(&cur->timestamp, time_str, sizeof(time_str));
        }
        printf("[%s] %s\n", time_str, cur->description);
        cur = cur->next;
    }

    free_timeline_list(head);
}
