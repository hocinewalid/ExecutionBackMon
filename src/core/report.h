#ifndef REPORT_H
#define REPORT_H

#include "executebackmon.h"

void report_investigation(const char* target, EvidenceNode* bam, EvidenceNode* pf, EvidenceNode* am, EvidenceNode* shim, EvidenceNode* ua, EvidenceNode* ev, ExecutionEvidence* pe_evidence, int score);

#endif // REPORT_H
