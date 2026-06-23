#include "executebackmon.h"
#include "core/timeline.h"
#include "core/scoring.h"
#include "core/report.h"
#include "core/ioc.h"
#include "utils.h"

#include "modules/bam.h"
#include "modules/prefetch.h"
#include "modules/amcache.h"
#include "modules/shimcache.h"
#include "modules/userassist.h"
#include "modules/eventlog.h"
#include "modules/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void investigate_executable(const char* target) {
    EvidenceNode* bam = bam_investigate(target);
    EvidenceNode* pf = prefetch_investigate(target);
    EvidenceNode* am = amcache_investigate(target);
    EvidenceNode* shim = shimcache_investigate(target);
    EvidenceNode* ua = userassist_investigate(target);
    EvidenceNode* ev = eventlog_investigate(target);

    ExecutionEvidence pe_evidence = {0};
    
    // Check if target is a full path on disk to do PE analysis
    DWORD attrs = GetFileAttributesA(target);
    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        pe_analyze(target, &pe_evidence);
    }

    int score = calculate_confidence_score(bam, pf, am, shim, ua, ev);

    report_investigation(target, bam, pf, am, shim, ua, ev, &pe_evidence, score);

    free_evidence_list(bam);
    free_evidence_list(pf);
    free_evidence_list(am);
    free_evidence_list(shim);
    free_evidence_list(ua);
    free_evidence_list(ev);
}

void print_usage(void) {
    printf("ExecuteBackMon - Reconstructing Windows Execution History\n");
    printf("Usage:\n");
    printf("  executebackmon.exe investigate \"<executable_name_or_path>\"\n");
    printf("  executebackmon.exe timeline\n");
    printf("  executebackmon.exe ioc <indicators.txt>\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "investigate") == 0) {
        if (argc < 3) {
            printf("Error: Missing target for investigate.\n");
            return 1;
        }
        investigate_executable(argv[2]);
    } else if (strcmp(argv[1], "timeline") == 0) {
        generate_timeline();
    } else if (strcmp(argv[1], "ioc") == 0) {
        if (argc < 3) {
            printf("Error: Missing IOC file.\n");
            return 1;
        }
        scan_iocs(argv[2]);
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
