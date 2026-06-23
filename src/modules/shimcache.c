#include "shimcache.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define SHIMCACHE_KEY "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"

static void parse_shimcache(const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    HKEY shim_key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, SHIMCACHE_KEY, 0, KEY_READ, &shim_key) != ERROR_SUCCESS) {
        return;
    }

    DWORD data_len;
    if (RegQueryValueExA(shim_key, "AppCompatCache", NULL, NULL, NULL, &data_len) == ERROR_SUCCESS) {
        BYTE* data = xmalloc(data_len);
        if (RegQueryValueExA(shim_key, "AppCompatCache", NULL, NULL, data, &data_len) == ERROR_SUCCESS) {
            
            // Heuristic search for unicode string target
            if (target) {
                // Convert target to wide char (uppercase)
                char target_upper[MAX_PATH_LEN];
                strncpy(target_upper, target, MAX_PATH_LEN - 1);
                target_upper[MAX_PATH_LEN - 1] = '\0';
                for (int i = 0; target_upper[i]; i++) {
                    target_upper[i] = toupper((unsigned char)target_upper[i]);
                }
                
                WCHAR target_w[MAX_PATH_LEN];
                MultiByteToWideChar(CP_UTF8, 0, target_upper, -1, target_w, MAX_PATH_LEN);
                size_t target_w_len = wcslen(target_w) * sizeof(WCHAR);

                // Very naive byte search for the wide string in the binary blob
                for (DWORD i = 0; i < data_len - target_w_len; i++) {
                    if (memcmp(data + i, target_w, target_w_len) == 0) {
                        if (e_head) {
                            EvidenceNode* node = create_evidence_node();
                            node->evidence.type = ARTIFACT_SHIMCACHE;
                            node->evidence.found = true;
                            strncpy(node->evidence.executable_path, target, MAX_PATH_LEN - 1);
                            node->evidence.has_last_execution = false;
                            append_evidence_node(e_head, node);
                        }
                        if (t_head) {
                            TimelineEntry* entry = create_timeline_entry();
                            entry->source_artifact = ARTIFACT_SHIMCACHE;
                            snprintf(entry->description, sizeof(entry->description), "ShimCache reference found for %s", target);
                            append_timeline_entry(t_head, entry);
                        }
                        break; // Found one instance, good enough for this basic heuristic
                    }
                }
            }
        }
        free(data);
    }
    RegCloseKey(shim_key);
}

EvidenceNode* shimcache_investigate(const char* target) {
    EvidenceNode* head = NULL;
    parse_shimcache(target, &head, NULL);
    return head;
}

TimelineEntry* shimcache_get_timeline(void) {
    TimelineEntry* head = NULL;
    // For a real timeline we'd parse all entries. For this skeleton we return empty for full timeline
    // unless we fully reverse engineer the struct.
    return head;
}

