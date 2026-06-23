#include "userassist.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sddl.h>

#define USERASSIST_SUBKEY "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

static void parse_userassist_key(HKEY root_key, const char* sid_str, const char* target, EvidenceNode** head, TimelineEntry** timeline_head) {
    HKEY user_key;
    if (RegOpenKeyExA(root_key, sid_str, 0, KEY_READ, &user_key) != ERROR_SUCCESS) {
        return;
    }

    char username[MAX_USERNAME_LEN] = {0};
    // Reusing the logic from bam, let's just do a simple fallback
    strncpy(username, sid_str, MAX_USERNAME_LEN - 1);
    
    // Now open UserAssist
    HKEY ua_key;
    if (RegOpenKeyExA(user_key, USERASSIST_SUBKEY, 0, KEY_READ, &ua_key) != ERROR_SUCCESS) {
        RegCloseKey(user_key);
        return;
    }

    DWORD guids_count, max_guid_len;
    if (RegQueryInfoKeyA(ua_key, NULL, NULL, NULL, &guids_count, &max_guid_len, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char* guid_name = xmalloc(max_guid_len + 1);
        for (DWORD i = 0; i < guids_count; i++) {
            DWORD name_len = max_guid_len + 1;
            if (RegEnumKeyExA(ua_key, i, guid_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                // Open Count subkey
                char count_path[512];
                snprintf(count_path, sizeof(count_path), "%s\\Count", guid_name);
                HKEY count_key;
                if (RegOpenKeyExA(ua_key, count_path, 0, KEY_READ, &count_key) == ERROR_SUCCESS) {
                    DWORD values_count, max_value_name_len, max_value_len;
                    if (RegQueryInfoKeyA(count_key, NULL, NULL, NULL, NULL, NULL, NULL, &values_count, &max_value_name_len, &max_value_len, NULL, NULL) == ERROR_SUCCESS) {
                        char* value_name = xmalloc(max_value_name_len + 1);
                        BYTE* value_data = xmalloc(max_value_len + 1);

                        for (DWORD j = 0; j < values_count; j++) {
                            DWORD vname_len = max_value_name_len + 1;
                            DWORD vdata_len = max_value_len + 1;
                            DWORD type;
                            if (RegEnumValueA(count_key, j, value_name, &vname_len, NULL, &type, value_data, &vdata_len) == ERROR_SUCCESS) {
                                if (type == REG_BINARY && vdata_len >= 72) {
                                    // Decode ROT13
                                    char decoded_name[MAX_PATH_LEN];
                                    strncpy(decoded_name, value_name, MAX_PATH_LEN - 1);
                                    decoded_name[MAX_PATH_LEN - 1] = '\0';
                                    rot13_decode(decoded_name);

                                    // Parse data (Win7+ 72 bytes)
                                    // Bytes 4-7: Run count
                                    // Bytes 60-67: FILETIME
                                    int run_count = 0;
                                    memcpy(&run_count, value_data + 4, 4);

                                    FILETIME ft;
                                    memcpy(&ft, value_data + 60, sizeof(FILETIME));

                                    // Target check
                                    if (target && head) {
                                        char decoded_lower[MAX_PATH_LEN];
                                        strncpy(decoded_lower, decoded_name, MAX_PATH_LEN - 1);
                                        decoded_lower[MAX_PATH_LEN - 1] = '\0';
                                        str_to_lower(decoded_lower);

                                        char target_lower[MAX_PATH_LEN];
                                        strncpy(target_lower, target, MAX_PATH_LEN - 1);
                                        target_lower[MAX_PATH_LEN - 1] = '\0';
                                        str_to_lower(target_lower);

                                        if (strstr(decoded_lower, target_lower) != NULL) {
                                            EvidenceNode* node = create_evidence_node();
                                            node->evidence.type = ARTIFACT_USERASSIST;
                                            node->evidence.found = true;
                                            strncpy(node->evidence.executable_path, decoded_name, MAX_PATH_LEN - 1);
                                            strncpy(node->evidence.username, username, MAX_USERNAME_LEN - 1);
                                            node->evidence.run_count = run_count;
                                            if (ft.dwHighDateTime != 0 || ft.dwLowDateTime != 0) {
                                                filetime_to_systemtime(&ft, &node->evidence.last_execution);
                                                node->evidence.has_last_execution = true;
                                            }
                                            append_evidence_node(head, node);
                                        }
                                    }

                                    // Timeline
                                    if (timeline_head && (ft.dwHighDateTime != 0 || ft.dwLowDateTime != 0)) {
                                        TimelineEntry* entry = create_timeline_entry();
                                        filetime_to_systemtime(&ft, &entry->timestamp);
                                        entry->source_artifact = ARTIFACT_USERASSIST;
                                        snprintf(entry->description, sizeof(entry->description), "UserAssist execution (Run Count: %d) by %s: %s", run_count, username, decoded_name);
                                        append_timeline_entry(timeline_head, entry);
                                    }
                                }
                            }
                        }
                        free(value_name);
                        free(value_data);
                    }
                    RegCloseKey(count_key);
                }
            }
        }
        free(guid_name);
    }
    RegCloseKey(ua_key);
    RegCloseKey(user_key);
}

static void iterate_users(const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    HKEY users_root;
    if (RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &users_root) != ERROR_SUCCESS) {
        return;
    }

    DWORD subkeys_count, max_subkey_len;
    if (RegQueryInfoKeyA(users_root, NULL, NULL, NULL, &subkeys_count, &max_subkey_len, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char* subkey_name = xmalloc(max_subkey_len + 1);
        for (DWORD i = 0; i < subkeys_count; i++) {
            DWORD name_len = max_subkey_len + 1;
            if (RegEnumKeyExA(users_root, i, subkey_name, &name_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                // Ignore _Classes keys
                if (!ends_with(subkey_name, "_Classes")) {
                    parse_userassist_key(users_root, subkey_name, target, e_head, t_head);
                }
            }
        }
        free(subkey_name);
    }
    RegCloseKey(users_root);
}

EvidenceNode* userassist_investigate(const char* target) {
    EvidenceNode* head = NULL;
    iterate_users(target, &head, NULL);
    return head;
}

TimelineEntry* userassist_get_timeline(void) {
    TimelineEntry* head = NULL;
    iterate_users(NULL, NULL, &head);
    return head;
}

