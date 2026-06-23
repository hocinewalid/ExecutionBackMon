#include "report.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_time(const SYSTEMTIME* st) {
    if (st && st->wYear != 0) {
        char buf[64];
        systemtime_to_string(st, buf, sizeof(buf));
        printf("%s\n", buf);
    } else {
        printf("Unknown\n");
    }
}

void report_investigation(const char* target, EvidenceNode* bam, EvidenceNode* pf, EvidenceNode* am, EvidenceNode* shim, EvidenceNode* ua, EvidenceNode* ev, ExecutionEvidence* pe_evidence, int score) {
    printf("Executable:\n%s\n\n", target);
    printf("Evidence:\n\n");

    printf("BAM:\n");
    if (bam) {
        printf("Found\nLast Execution:\n");
        print_time(&bam->evidence.last_execution);
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    printf("Prefetch:\n");
    if (pf) {
        printf("Found\nRun Count:\n%d\n", pf->evidence.run_count); // Stub might be 0
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    printf("AmCache:\n");
    if (am) {
        printf("Found\nPublisher:\n%s\n", am->evidence.publisher);
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    printf("ShimCache:\n");
    if (shim) {
        printf("Found\n");
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    printf("UserAssist:\n");
    if (ua) {
        printf("Found\nRun Count:\n%d\n", ua->evidence.run_count);
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    printf("Sysmon/EventLog:\n");
    if (ev) {
        printf("Found\nCommand Line:\n%s\n", ev->evidence.command_line);
    } else {
        printf("Not Found\n");
    }
    printf("\n");

    if (pe_evidence && pe_evidence->found) {
        printf("PE Analysis:\n");
        printf("MD5: %s\n", pe_evidence->md5);
        printf("SHA1: %s\n", pe_evidence->sha1);
        printf("SHA256: %s\n", pe_evidence->sha256);
        printf("Authenticode: %s\n\n", pe_evidence->publisher);
    }

    printf("Confidence Score:\n%d%%\n\n", score);

    printf("Assessment:\n");
    if (score >= 80) {
        printf("Strong evidence that the executable was executed.\n");
    } else if (score >= 40) {
        printf("Moderate evidence that the executable was executed.\n");
    } else if (score > 0) {
        printf("Weak evidence that the executable was executed.\n");
    } else {
        printf("No evidence found.\n");
    }
    printf("\n");
}
