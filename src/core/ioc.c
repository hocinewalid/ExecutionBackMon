#include "ioc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void scan_iocs(const char* ioc_file) {
    FILE* fp = fopen(ioc_file, "r");
    if (!fp) {
        printf("Failed to open IOC file: %s\n", ioc_file);
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        printf("\nScanning for IOC: %s\n", line);
        investigate_executable(line);
    }
    fclose(fp);
}
