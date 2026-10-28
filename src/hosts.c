// winspect hosts - the active lines of the system hosts file
//
// %SystemRoot%\System32\drivers\etc\hosts maps names to addresses before DNS is
// consulted, so a single line here can silently redirect a domain to an attacker
// or block security vendors. The file is plain text; we read it, drop comments
// and blank lines, and print each real entry (address + the names it maps).
// Read-only - we only read the file.

#include "hosts.h"
#include "jsonutil.h"
#include "ioc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int cmd_hosts(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "hosts: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    char path[MAX_PATH];
    UINT wl = GetSystemWindowsDirectoryA(path, MAX_PATH);
    if (wl == 0 || wl >= MAX_PATH) {
        fputs("hosts: cannot resolve the Windows directory\n", stderr);
        return 1;
    }
    snprintf(path + wl, sizeof path - wl, "\\System32\\drivers\\etc\\hosts");

    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "hosts: cannot open '%s' (error %lu)\n", path, (unsigned long)GetLastError());
        return 1;
    }
    LARGE_INTEGER sz;
    char *buf = NULL;
    if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1 << 20)) {
        buf = (char *)malloc((size_t)sz.QuadPart + 1);
        DWORD got = 0;
        if (buf != NULL && ReadFile(f, buf, (DWORD)sz.QuadPart, &got, NULL)) {
            buf[got] = '\0';
        } else {
            free(buf); buf = NULL;
        }
    }
    CloseHandle(f);
    if (buf == NULL) {
        fputs("hosts: could not read the hosts file\n", stderr);
        return 1;
    }

    if (mode == 0) {
        printf("hosts  %s\n\n", path);
        printf("      %-8s %-40s %s\n", "kind", "address", "names");
    } else if (mode == 2) {
        puts("address,names,kind,scope");
    } else {
        putchar('[');
    }

    unsigned count = 0, redirects = 0;
    int first = 1;
    for (char *line = strtok(buf, "\r\n"); line != NULL; line = strtok(NULL, "\r\n")) {
        char *p = line;
        while (*p == ' ' || *p == '\t') { p++; }
        if (*p == '\0' || *p == '#') {
            continue;   // blank or comment
        }
        // First whitespace-separated token is the address; the remainder is the
        // name list (possibly several names, kept as written).
        char *addr = p;
        char *sp = p;
        while (*sp && *sp != ' ' && *sp != '\t') { sp++; }
        if (*sp == '\0') {
            continue;   // no name after the address: not a real mapping
        }
        *sp = '\0';
        char *names = sp + 1;
        while (*names == ' ' || *names == '\t') { names++; }
        // Trim a trailing inline comment.
        char *hash = strchr(names, '#');
        if (hash != NULL) { *hash = '\0'; }
        // Trim trailing whitespace on names.
        size_t nl = strlen(names);
        while (nl > 0 && (names[nl - 1] == ' ' || names[nl - 1] == '\t')) { names[--nl] = '\0'; }
        if (names[0] == '\0') {
            continue;
        }

        // IPv6 loopback / unspecified are "block" too; other IPv6 is a redirect.
        const char *scope = ioc_ip_scope(addr);
        if (scope[0] == '\0') {
            scope = (strcmp(addr, "::1") == 0) ? "loopback"
                  : (strcmp(addr, "::") == 0) ? "unspecified" : "ipv6/other";
        }
        int block = strcmp(scope, "loopback") == 0 || strcmp(scope, "unspecified") == 0;
        const char *kind = block ? "block" : "redirect";
        if (!block) { redirects++; }

        count++;
        if (mode == 0) {
            printf("  %s%-8s %-40s %s\n", block ? "    " : "[!] ", kind, addr, names);
        } else if (mode == 2) {
            csv_str(addr); putchar(',');
            csv_str(names); putchar(',');
            csv_str(kind); putchar(',');
            csv_str(scope); putchar('\n');
        } else {
            printf("%s{\"address\":", first ? "" : ",");
            json_str(addr);
            fputs(",\"names\":", stdout); json_str(names);
            fputs(",\"kind\":", stdout);  json_str(kind);
            fputs(",\"scope\":", stdout); json_str(scope);
            printf(",\"suspicious\":%s}", block ? "false" : "true");
            first = 0;
        }
    }
    free(buf);

    if (mode == 0) {
        printf("\n%u active entr%s, %u redirect%s (flagged)\n", count, count == 1 ? "y" : "ies",
               redirects, redirects == 1 ? "" : "s");
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
