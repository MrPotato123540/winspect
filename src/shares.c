// winspect shares - the SMB shares this machine offers
//
// Shares are how files and the admin surface are reached over the network, so
// "what is shared, and is anything shared that shouldn't be?" is a baseline
// question. NetShareEnum at level 1 lists each share's name, type and comment
// without needing admin. We mark the special administrative shares (C$, ADMIN$,
// IPC$) so an unexpected non-special share stands out. Read-only enumeration.

#include "shares.h"
#include "jsonutil.h"

#include <windows.h>
#include <lm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void w2u(const WCHAR *w, char *out, size_t n)
{
    out[0] = '\0';
    if (w != NULL) {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)n, NULL, NULL);
    }
}

static const char *share_type(DWORD t)
{
    switch (t & 3) {   // STYPE_MASK: isolate the base type from the flag bits
    case STYPE_DISKTREE: return "disk";
    case STYPE_PRINTQ:   return "printer";
    case STYPE_DEVICE:   return "device";
    case STYPE_IPC:      return "ipc";
    default:             return "?";
    }
}

int cmd_shares(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "shares: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    PSHARE_INFO_1 buf = NULL;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS st = NetShareEnum(NULL, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                                     &read, &total, &resume);
    // ERROR_MORE_DATA can come back with a partial buffer; we print what we got.
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        fprintf(stderr, "shares: NetShareEnum failed (status %lu)\n", (unsigned long)st);
        return 1;
    }

    if (mode == 0) {
        printf("  %-18s %-8s %-9s %s\n", "name", "type", "flags", "comment");
    } else if (mode == 2) {
        puts("name,type,special,comment");
    } else {
        putchar('[');
    }

    int first = 1;
    for (DWORD i = 0; i < read; i++) {
        char name[128], remark[512];
        w2u(buf[i].shi1_netname, name, sizeof name);
        w2u(buf[i].shi1_remark, remark, sizeof remark);
        int special = (buf[i].shi1_type & STYPE_SPECIAL) != 0;
        const char *type = share_type(buf[i].shi1_type);

        if (mode == 0) {
            printf("  %-18s %-8s %-9s %s\n", name, type,
                   special ? "special" : "-", remark);
        } else if (mode == 2) {
            csv_str(name);   putchar(',');
            csv_str(type);   printf(",%d,", special ? 1 : 0);
            csv_str(remark); putchar('\n');
        } else {
            printf("%s{\"name\":", first ? "" : ",");
            json_str(name);
            fputs(",\"type\":", stdout);    json_str(type);
            printf(",\"special\":%s,\"comment\":", special ? "true" : "false");
            json_str(remark);
            putchar('}');
            first = 0;
        }
    }
    if (buf != NULL) {
        NetApiBufferFree(buf);
    }

    if (mode == 0) {
        printf("\n%lu share(s)\n", (unsigned long)read);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
