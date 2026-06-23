#ifndef EXECUTEBACKMON_H
#define EXECUTEBACKMON_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_PATH_LEN 32768
#define MAX_USERNAME_LEN 256
#define MAX_CMD_LINE 8192
#define MAX_HASH_LEN 65

typedef enum {
    ARTIFACT_BAM,
    ARTIFACT_PREFETCH,
    ARTIFACT_AMCACHE,
    ARTIFACT_SHIMCACHE,
    ARTIFACT_USERASSIST,
    ARTIFACT_EVENTLOG,
    ARTIFACT_PE
} ArtifactType;

typedef struct {
    ArtifactType type;
    bool found;
    char executable_path[MAX_PATH_LEN];
    char executable_name[MAX_PATH_LEN];
    
    // Time information
    SYSTEMTIME last_execution;
    bool has_last_execution;
    
    // Module specific fields
    int run_count;
    char username[MAX_USERNAME_LEN];
    char command_line[MAX_CMD_LINE];
    char publisher[256];
    char sha1[MAX_HASH_LEN];
    char sha256[MAX_HASH_LEN];
    char md5[MAX_HASH_LEN];
    
} ExecutionEvidence;

// A node in a linked list of evidence
typedef struct EvidenceNode {
    ExecutionEvidence evidence;
    struct EvidenceNode* next;
} EvidenceNode;

// Timeline entry
typedef struct TimelineEntry {
    SYSTEMTIME timestamp;
    ArtifactType source_artifact;
    char description[1024];
    struct TimelineEntry* next;
} TimelineEntry;

// Core functions
void investigate_executable(const char* target);
void generate_timeline(void);
void scan_iocs(const char* ioc_file);

// Module declarations
EvidenceNode* bam_investigate(const char* target);
EvidenceNode* prefetch_investigate(const char* target);
EvidenceNode* amcache_investigate(const char* target);
EvidenceNode* shimcache_investigate(const char* target);
EvidenceNode* userassist_investigate(const char* target);
EvidenceNode* eventlog_investigate(const char* target);
void pe_analyze(const char* target_path, ExecutionEvidence* pe_evidence);

// Timeline parsing per module
TimelineEntry* bam_get_timeline(void);
TimelineEntry* prefetch_get_timeline(void);
TimelineEntry* amcache_get_timeline(void);
TimelineEntry* shimcache_get_timeline(void);
TimelineEntry* userassist_get_timeline(void);
TimelineEntry* eventlog_get_timeline(void);

#endif // EXECUTEBACKMON_H
