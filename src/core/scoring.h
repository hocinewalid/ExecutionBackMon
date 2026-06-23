#ifndef SCORING_H
#define SCORING_H

#include "executebackmon.h"

int calculate_confidence_score(EvidenceNode* bam, EvidenceNode* pf, EvidenceNode* am, EvidenceNode* shim, EvidenceNode* ua, EvidenceNode* ev);

#endif // SCORING_H
