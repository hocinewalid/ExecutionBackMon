#include "eventlog.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

static const wchar_t* QUERY = L"<QueryList>"
    L"<Query Id=\"0\" Path=\"Security\">"
    L"<Select Path=\"Security\">*[System[(EventID=4688 or EventID=4689 or EventID=4624 or EventID=4697)]]</Select>"
    L"</Query>"
    L"<Query Id=\"1\" Path=\"System\">"
    L"<Select Path=\"System\">*[System[(EventID=7045)]]</Select>"
    L"</Query>"
    L"<Query Id=\"2\" Path=\"Microsoft-Windows-Sysmon/Operational\">"
    L"<Select Path=\"Microsoft-Windows-Sysmon/Operational\">*[System[(EventID=1 or EventID=7 or EventID=11)]]</Select>"
    L"</Query>"
    L"</QueryList>";

static void process_event(EVT_HANDLE hEvent, const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    DWORD buffer_size = 0;
    DWORD property_count = 0;
    
    // Get required size
    EvtRender(NULL, hEvent, EvtRenderEventXml, buffer_size, NULL, &buffer_size, &property_count);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        wchar_t* xml_buf = (wchar_t*)xmalloc(buffer_size);
        if (EvtRender(NULL, hEvent, EvtRenderEventXml, buffer_size, xml_buf, &buffer_size, &property_count)) {
            // Convert to char*
            int len = WideCharToMultiByte(CP_UTF8, 0, xml_buf, -1, NULL, 0, NULL, NULL);
            char* xml_str = (char*)xmalloc(len);
            WideCharToMultiByte(CP_UTF8, 0, xml_buf, -1, xml_str, len, NULL, NULL);

            // Simple XML heuristic parsing to find the target and extract basic info
            char xml_lower[len];
            strncpy(xml_lower, xml_str, len);
            str_to_lower(xml_lower);
            
            char target_lower[MAX_PATH_LEN];
            if (target) {
                strncpy(target_lower, target, MAX_PATH_LEN - 1);
                target_lower[MAX_PATH_LEN - 1] = '\0';
                str_to_lower(target_lower);
            }

            if (!target || strstr(xml_lower, target_lower) != NULL) {
                // If it matches, let's extract EventID and TimeCreated
                // <EventID>4688</EventID>
                char* ev_id_start = strstr(xml_str, "<EventID>");
                int event_id = 0;
                if (ev_id_start) {
                    event_id = atoi(ev_id_start + 9);
                }

                // <TimeCreated SystemTime="2026-06-22T21:38:00.0000000Z"/>
                char* time_start = strstr(xml_str, "SystemTime=\"");
                SYSTEMTIME st = {0};
                if (time_start) {
                    time_start += 12;
                    int y, m, d, h, mn, s;
                    if (sscanf(time_start, "%04d-%02d-%02dT%02d:%02d:%02d", &y, &m, &d, &h, &mn, &s) == 6) {
                        st.wYear = y; st.wMonth = m; st.wDay = d;
                        st.wHour = h; st.wMinute = mn; st.wSecond = s;
                    }
                }

                if (target && e_head) {
                    EvidenceNode* node = create_evidence_node();
                    node->evidence.type = ARTIFACT_EVENTLOG;
                    node->evidence.found = true;
                    if (target) {
                        strncpy(node->evidence.executable_path, target, MAX_PATH_LEN - 1);
                    }
                    node->evidence.last_execution = st;
                    node->evidence.has_last_execution = true;
                    // Try to extract command line from 4688 or sysmon 1
                    char* cmd_start = strstr(xml_str, "CommandLine\">");
                    if (cmd_start) {
                        cmd_start += 13;
                        char* cmd_end = strchr(cmd_start, '<');
                        if (cmd_end) {
                            int len = cmd_end - cmd_start;
                            if (len >= MAX_CMD_LINE) len = MAX_CMD_LINE - 1;
                            strncpy(node->evidence.command_line, cmd_start, len);
                            node->evidence.command_line[len] = '\0';
                        }
                    }
                    append_evidence_node(e_head, node);
                }

                if (t_head) {
                    TimelineEntry* entry = create_timeline_entry();
                    entry->timestamp = st;
                    entry->source_artifact = ARTIFACT_EVENTLOG;
                    snprintf(entry->description, sizeof(entry->description), "Event ID %d triggered. Target found in payload.", event_id);
                    append_timeline_entry(t_head, entry);
                }
            }
            free(xml_str);
        }
        free(xml_buf);
    }
}

static void query_events(const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    EVT_HANDLE hResults = EvtQuery(NULL, NULL, QUERY, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) {
        return;
    }

    EVT_HANDLE hEvents[10];
    DWORD returned = 0;
    while (EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            process_event(hEvents[i], target, e_head, t_head);
            EvtClose(hEvents[i]);
        }
    }
    EvtClose(hResults);
}

EvidenceNode* eventlog_investigate(const char* target) {
    EvidenceNode* head = NULL;
    query_events(target, &head, NULL);
    return head;
}

TimelineEntry* eventlog_get_timeline(void) {
    TimelineEntry* head = NULL;
    query_events(NULL, NULL, &head);
    return head;
}

