#include "scoring.h"

int calculate_confidence_score(EvidenceNode* bam, EvidenceNode* pf, EvidenceNode* am, EvidenceNode* shim, EvidenceNode* ua, EvidenceNode* ev) {
    int score = 0;
    int max_score = 100;

    // Prefetch is very strong evidence of execution
    if (pf) score += 30;
    
    // UserAssist confirms UI execution
    if (ua) score += 20;

    // BAM confirms background/OS execution
    if (bam) score += 15;

    // EventLog (4688) is absolute proof if auditing is enabled
    if (ev) score += 35;

    // ShimCache shows it existed and might have been executed
    if (shim) score += 10;

    // AmCache shows it existed and was processed by app compat
    if (am) score += 5;

    if (score > max_score) score = max_score;
    
    return score;
}
