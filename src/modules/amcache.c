#include "amcache.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define AMCACHE_PATH "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"

EvidenceNode* amcache_investigate(const char* target) {
    // AmCache.hve is typically locked by the system.
    // In a full implementation, we would either parse a raw copy of the file (Regf format)
    // or use RegLoadAppKey on an acquired copy.
    // For this demonstration, we simulate finding the artifact if we can read the file 
    // and find the target string (which works if run against an offline copy).
    
    EvidenceNode* head = NULL;
    HANDLE hFile = CreateFileA(AMCACHE_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, NULL);
        if (size > 0 && size < 100 * 1024 * 1024) { // Limit to 100MB for safe memory
            BYTE* buf = xmalloc(size);
            DWORD read;
            if (ReadFile(hFile, buf, size, &read, NULL)) {
                if (target) {
                    char target_upper[MAX_PATH_LEN];
                    strncpy(target_upper, target, MAX_PATH_LEN - 1);
                    target_upper[MAX_PATH_LEN - 1] = '\0';
                    for (int i = 0; target_upper[i]; i++) {
                        target_upper[i] = toupper((unsigned char)target_upper[i]);
                    }

                    WCHAR target_w[MAX_PATH_LEN];
                    MultiByteToWideChar(CP_UTF8, 0, target_upper, -1, target_w, MAX_PATH_LEN);
                    size_t target_w_len = wcslen(target_w) * sizeof(WCHAR);

                    for (DWORD i = 0; i < read - target_w_len; i++) {
                        if (memcmp(buf + i, target_w, target_w_len) == 0) {
                            EvidenceNode* node = create_evidence_node();
                            node->evidence.type = ARTIFACT_AMCACHE;
                            node->evidence.found = true;
                            strncpy(node->evidence.executable_path, target, MAX_PATH_LEN - 1);
                            // Set dummy SHA1 for demonstration
                            strncpy(node->evidence.sha1, "0000000000000000000000000000000000000000", MAX_HASH_LEN - 1);
                            strncpy(node->evidence.publisher, "Unknown", 255);
                            append_evidence_node(&head, node);
                            break;
                        }
                    }
                }
            }
            free(buf);
        }
        CloseHandle(hFile);
    }
    return head;
}

TimelineEntry* amcache_get_timeline(void) {
    return NULL;
}

