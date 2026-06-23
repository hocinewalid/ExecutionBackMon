#include "prefetch.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef NTSTATUS(WINAPI *RtlDecompressBuffer_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

static RtlDecompressBuffer_t pRtlDecompressBuffer = NULL;

static void init_ntdll(void) {
    if (!pRtlDecompressBuffer) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pRtlDecompressBuffer = (RtlDecompressBuffer_t)GetProcAddress(hNtdll, "RtlDecompressBuffer");
        }
    }
}

static void parse_pf_file(const char* pf_path, const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    HANDLE hFile = CreateFileA(pf_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0) {
        CloseHandle(hFile);
        return;
    }

    BYTE* buf = xmalloc(size);
    DWORD read;
    ReadFile(hFile, buf, size, &read, NULL);
    CloseHandle(hFile);

    BYTE* uncompressed = NULL;
    DWORD uncompressed_size = 0;

    // Check for MAM signature
    if (size > 8 && buf[0] == 'M' && buf[1] == 'A' && buf[2] == 'M' && buf[3] == '\x04') {
        init_ntdll();
        if (pRtlDecompressBuffer) {
            uncompressed_size = *(DWORD*)(buf + 4);
            uncompressed = xmalloc(uncompressed_size);
            ULONG final_size = 0;
            // COMPRESSION_FORMAT_LZNT1 or XPRESS (0x0100 or 0x0002)
            // Usually 0x0002 | 0x0100 -> 0x0102 for MAM (Xpress Huffman)
            if (pRtlDecompressBuffer(0x0004 /* COMPRESSION_FORMAT_XPRESS_HUFF */, uncompressed, uncompressed_size, buf + 8, size - 8, &final_size) != 0) {
                // Try XPRESS
                if (pRtlDecompressBuffer(0x0002 /* COMPRESSION_FORMAT_XPRESS */, uncompressed, uncompressed_size, buf + 8, size - 8, &final_size) != 0) {
                    free(uncompressed);
                    uncompressed = NULL;
                }
            }
        }
    } else {
        // Uncompressed (Win7)
        uncompressed = xmalloc(size);
        memcpy(uncompressed, buf, size);
        uncompressed_size = size;
    }

    free(buf);

    if (uncompressed) {
        char target_upper[MAX_PATH_LEN] = {0};
        if (target) {
            strncpy(target_upper, target, MAX_PATH_LEN - 1);
            for (int i = 0; target_upper[i]; i++) {
                target_upper[i] = toupper((unsigned char)target_upper[i]);
            }
        }

        char pf_name[MAX_PATH_LEN];
        strncpy(pf_name, strrchr(pf_path, '\\') ? strrchr(pf_path, '\\') + 1 : pf_path, MAX_PATH_LEN - 1);

        if (!target || strstr(pf_name, target_upper) != NULL) {
            if (e_head && target) {
                EvidenceNode* node = create_evidence_node();
                node->evidence.type = ARTIFACT_PREFETCH;
                node->evidence.found = true;
                strncpy(node->evidence.executable_path, pf_name, MAX_PATH_LEN - 1);

                // Very basic heuristic for FILETIME in Win10 prefetch (offsets vary drastically)
                // We'll skip precise extraction in this skeleton.
                node->evidence.has_last_execution = false;
                append_evidence_node(e_head, node);
            }
            if (t_head) {
                TimelineEntry* entry = create_timeline_entry();
                entry->source_artifact = ARTIFACT_PREFETCH;
                snprintf(entry->description, sizeof(entry->description), "Prefetch artifact found: %s", pf_name);
                append_timeline_entry(t_head, entry);
            }
        }
        free(uncompressed);
    }
}

static void scan_prefetch(const char* target, EvidenceNode** e_head, TimelineEntry** t_head) {
    char search_path[MAX_PATH];
    GetWindowsDirectoryA(search_path, MAX_PATH);
    strncat(search_path, "\\Prefetch\\*.pf", MAX_PATH - strlen(search_path) - 1);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search_path, &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char full_path[MAX_PATH];
            GetWindowsDirectoryA(full_path, MAX_PATH);
            strncat(full_path, "\\Prefetch\\", MAX_PATH - strlen(full_path) - 1);
            strncat(full_path, findData.cFileName, MAX_PATH - strlen(full_path) - 1);
            
            parse_pf_file(full_path, target, e_head, t_head);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
}

EvidenceNode* prefetch_investigate(const char* target) {
    EvidenceNode* head = NULL;
    scan_prefetch(target, &head, NULL);
    return head;
}

TimelineEntry* prefetch_get_timeline(void) {
    TimelineEntry* head = NULL;
    scan_prefetch(NULL, NULL, &head);
    return head;
}

