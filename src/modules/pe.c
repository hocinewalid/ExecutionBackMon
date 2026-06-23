#include "pe.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define BUFSIZE 1024

static void calculate_hash(const char* filepath, ALG_ID alg_id, char* hash_out, size_t max_len) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[64];
    DWORD cbHash = 0;
    char rgbDigits[] = "0123456789abcdef";

    hash_out[0] = '\0';

    hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, alg_id, 0, 0, &hHash)) {
            while (ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
                if (cbRead == 0) break;
                CryptHashData(hHash, rgbFile, cbRead, 0);
            }
            cbHash = sizeof(rgbHash);
            if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                if ((cbHash * 2 + 1) <= max_len) {
                    for (DWORD i = 0; i < cbHash; i++) {
                        snprintf(&hash_out[i * 2], 3, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
                    }
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
}

static bool verify_authenticode(const char* filepath, char* publisher, size_t pub_len) {
    WCHAR wszFilePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filepath, -1, wszFilePath, MAX_PATH);

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = wszFilePath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    // If publisher needs to be extracted, we'd query WTHelperProvDataFromStateData etc.
    // For simplicity, just return verified status, and set publisher string
    if (lStatus == ERROR_SUCCESS) {
        strncpy(publisher, "Verified Signature", pub_len - 1);
        publisher[pub_len - 1] = '\0';
    } else {
        strncpy(publisher, "Unknown / Unsigned", pub_len - 1);
        publisher[pub_len - 1] = '\0';
    }

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return (lStatus == ERROR_SUCCESS);
}

void pe_analyze(const char* target_path, ExecutionEvidence* pe_evidence) {
    if (!target_path || !pe_evidence) return;
    
    pe_evidence->type = ARTIFACT_PE;
    pe_evidence->found = true;

    calculate_hash(target_path, CALG_MD5, pe_evidence->md5, MAX_HASH_LEN);
    calculate_hash(target_path, CALG_SHA1, pe_evidence->sha1, MAX_HASH_LEN);
    calculate_hash(target_path, CALG_SHA_256, pe_evidence->sha256, MAX_HASH_LEN);

    verify_authenticode(target_path, pe_evidence->publisher, sizeof(pe_evidence->publisher));
}

