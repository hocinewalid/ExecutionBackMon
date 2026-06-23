#include "bam.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sddl.h>

#define BAM_KEY "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"

static void resolve_sid_to_username(const char* sid_str, char* username, size_t max_len) {
    PSID sid = NULL;
    if (ConvertStringSidToSidA(sid_str, &sid)) {
        char name[256];
        char domain[256];
        DWORD name_len = sizeof(name);
        DWORD domain_len = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, sid, name, &name_len, domain, &domain_len, &use)) {
            snprintf(username, max_len, "%s\\%s", domain, name);
        } else {
            strncpy(username, sid_str, max_len - 1);
        }
        LocalFree(sid);
    } else {
        strncpy(username, sid_str, max_len - 1);
    }
}

static void parse_bam_sid_key(HKEY root_key, const char* sid_str, const char* target, EvidenceNode** head) {
    HKEY user_key;
    if (RegOpenKeyExA(root_key, sid_str, 0, KEY_READ, &user_key) != ERROR_SUCCESS) {
        return;
    }

    char username[MAX_USERNAME_LEN] = {0};
    resolve_sid_to_username(sid_str, username, sizeof(username));

    DWORD values_count, max_value_name_len, max_value_len;
    if (RegQueryInfoKeyA(user_key, NULL, NULL, NULL, NULL, NULL, NULL, &values_count, &max_value_name_len, &max_value_len, NULL, NULL) == ERROR_SUCCESS) {
        char* value_name = xmalloc(max_value_name_len + 1);
        BYTE* value_data = xmalloc(max_value_len + 1);

        for (DWORD i = 0; i < values_count; i++) {
            DWORD name_len = max_value_name_len + 1;
            DWORD data_len = max_value_len + 1;
            DWORD type;
            if (RegEnumValueA(user_key, i, value_name, &name_len, NULL, &type, value_data, &data_len) == ERROR_SUCCESS) {
                if (type == REG_BINARY && data_len >= 8) {
                    // Check if target matches
                    // target could be "w.exe" or "C:\...\w.exe"
                    char value_name_lower[MAX_PATH_LEN];
                    strncpy(value_name_lower, value_name, MAX_PATH_LEN - 1);
                    value_name_lower[MAX_PATH_LEN - 1] = '\0';
                    str_to_lower(value_name_lower);

                    char target_lower[MAX_PATH_LEN];
                    strncpy(target_lower, target, MAX_PATH_LEN - 1);
                    target_lower[MAX_PATH_LEN - 1] = '\0';
                    str_to_lower(target_lower);

                    if (strstr(value_name_lower, target_lower) != NULL) {
                        EvidenceNode* node = create_evidence_node();
                        node->evidence.type = ARTIFACT_BAM;
                        node->evidence.found = true;
                        strncpy(node->evidence.executable_path, value_name, MAX_PATH_LEN - 1);
                        strncpy(node->evidence.username, username, MAX_USERNAME_LEN - 1);
                        
                        FILETIME ft;
                        memcpy(&ft, value_data, sizeof(FILETIME));
                        filetime_to_systemtime(&ft, &node->evidence.last_execution);
                        node->evidence.has_last_execution = true;

                        append_evidence_node(head, node);
                    }
                }
            }
        }
        free(value_name);
        free(value_data);
    }
    RegCloseKey(user_key);
}

EvidenceNode* bam_investigate(const char* target) {
    EvidenceNode* head = NULL;
    HKEY bam_root;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, BAM_KEY, 0, KEY_READ, &bam_root) != ERROR_SUCCESS) {
        return NULL;
    }

    DWORD subkeys_count, max_subkey_len;
    if (RegQueryInfoKeyA(bam_root, NULL, NULL, NULL, &subkeys_count, &max_subkey_len, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char* subkey_name = xmalloc(max_subkey_len + 1);
        for (DWORD i = 0; i < subkeys_count; i++) {
            DWORD name_len = max_subkey_len + 1;
            if (RegEnumKeyExA(bam_root, i, subkey_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                parse_bam_sid_key(bam_root, subkey_name, target, &head);
            }
        }
        free(subkey_name);
    }

    RegCloseKey(bam_root);
    return head;
}

TimelineEntry* bam_get_timeline(void) {
    TimelineEntry* head = NULL;
    HKEY bam_root;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, BAM_KEY, 0, KEY_READ, &bam_root) != ERROR_SUCCESS) {
        return NULL;
    }

    DWORD subkeys_count, max_subkey_len;
    if (RegQueryInfoKeyA(bam_root, NULL, NULL, NULL, &subkeys_count, &max_subkey_len, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char* subkey_name = xmalloc(max_subkey_len + 1);
        for (DWORD i = 0; i < subkeys_count; i++) {
            DWORD name_len = max_subkey_len + 1;
            if (RegEnumKeyExA(bam_root, i, subkey_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY user_key;
                if (RegOpenKeyExA(bam_root, subkey_name, 0, KEY_READ, &user_key) == ERROR_SUCCESS) {
                    char username[MAX_USERNAME_LEN] = {0};
                    resolve_sid_to_username(subkey_name, username, sizeof(username));

                    DWORD values_count, max_value_name_len, max_value_len;
                    if (RegQueryInfoKeyA(user_key, NULL, NULL, NULL, NULL, NULL, NULL, &values_count, &max_value_name_len, &max_value_len, NULL, NULL) == ERROR_SUCCESS) {
                        char* value_name = xmalloc(max_value_name_len + 1);
                        BYTE* value_data = xmalloc(max_value_len + 1);

                        for (DWORD j = 0; j < values_count; j++) {
                            DWORD vname_len = max_value_name_len + 1;
                            DWORD vdata_len = max_value_len + 1;
                            DWORD type;
                            if (RegEnumValueA(user_key, j, value_name, &vname_len, NULL, &type, value_data, &vdata_len) == ERROR_SUCCESS) {
                                if (type == REG_BINARY && vdata_len >= 8) {
                                    FILETIME ft;
                                    memcpy(&ft, value_data, sizeof(FILETIME));
                                    
                                    TimelineEntry* entry = create_timeline_entry();
                                    filetime_to_systemtime(&ft, &entry->timestamp);
                                    entry->source_artifact = ARTIFACT_BAM;
                                    snprintf(entry->description, sizeof(entry->description), "BAM execution by %s: %s", username, value_name);
                                    append_timeline_entry(&head, entry);
                                }
                            }
                        }
                        free(value_name);
                        free(value_data);
                    }
                    RegCloseKey(user_key);
                }
            }
        }
        free(subkey_name);
    }
    RegCloseKey(bam_root);
    return head;
}

