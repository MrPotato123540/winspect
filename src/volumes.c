// winspect volumes - mounted volumes and their serial numbers
//
// GetLogicalDriveStrings lists the drive letters; GetVolumeInformation gives
// label, serial and file system; GetDiskFreeSpaceEx the sizes;
// GetVolumeNameForVolumeMountPoint the \\?\Volume{GUID}\ path that stays the
// same when the letter changes. Read-only: nothing is mounted or changed.

#include "volumes.h"
#include "ioc.h"
#include "jsonutil.h"

#include <windows.h>
#include <winnetwk.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *type_name(UINT t)
{
    switch (t) {
    case DRIVE_REMOVABLE: return "removable";
    case DRIVE_FIXED:     return "fixed";
    case DRIVE_REMOTE:    return "network";
    case DRIVE_CDROM:     return "cdrom";
    case DRIVE_RAMDISK:   return "ramdisk";
    case DRIVE_NO_ROOT_DIR: return "no volume";
    default:              return "unknown";
    }
}

static void human(uint64_t b, char *out, size_t n)
{
    static const char *const u[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double v = (double)b;
    int i = 0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; i++; }
    snprintf(out, n, i ? "%.1f %s" : "%.0f %s", v, u[i]);
}

int cmd_volumes(int argc, char **argv)
{
    int mode = 0;
    const char *find = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else if (strcmp(argv[a], "--find") == 0 && a + 1 < argc) find = argv[++a];
        else {
            fprintf(stderr, "volumes: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    char drives[512];
    DWORD len = GetLogicalDriveStringsA(sizeof drives - 1, drives);
    if (len == 0 || len >= sizeof drives) {
        if (mode == 1) puts("[]");
        fprintf(stderr, "volumes: cannot list drives (error %lu)\n", (unsigned long)GetLastError());
        return 1;
    }
    // A drive with no medium (empty card reader) must not pop up a dialog.
    UINT oldmode = SetErrorMode(SEM_FAILCRITICALERRORS);
    if (mode == 0) {
        puts("volumes  (serial = what lnk / jumplist / prefetch record for the volume a file was on)\n");
        printf("    %-4s %-10s %-9s  %-8s %-20s %10s %10s  %s\n", "", "type", "serial", "fs", "label", "size", "free", "volume / remote path");
    } else if (mode == 2) {
        puts("drive,type,serial,serial_hex,file_system,label,size,free,volume,remote");
    } else {
        putchar('[');
    }
    unsigned shown = 0;
    for (const char *d = drives; *d; d += strlen(d) + 1) {
        UINT type = GetDriveTypeA(d);
        char label[MAX_PATH] = "", fs[MAX_PATH] = "", guid[MAX_PATH] = "", remote[MAX_PATH] = "";
        DWORD serial = 0, maxlen = 0, flags = 0;
        int have = GetVolumeInformationA(d, label, sizeof label, &serial, &maxlen, &flags, fs, sizeof fs) != 0;
        ULARGE_INTEGER avail, total, freeb;
        total.QuadPart = freeb.QuadPart = 0;
        int have_size = have && GetDiskFreeSpaceExA(d, &avail, &total, &freeb);
        if (type != DRIVE_REMOTE) GetVolumeNameForVolumeMountPointA(d, guid, sizeof guid);
        else {
            char letter[3] = { d[0], ':', 0 };
            DWORD rl = sizeof remote;
            if (WNetGetConnectionA(letter, remote, &rl) != NO_ERROR) remote[0] = '\0';
        }
        char s1[16] = "", s2[16] = "", letter[3] = { d[0], ':', 0 };
        if (have) {
            snprintf(s1, sizeof s1, "%04X-%04X", (unsigned)(serial >> 16), (unsigned)(serial & 0xFFFF));
            snprintf(s2, sizeof s2, "%08lX", (unsigned long)serial);
        }
        if (find && !ioc_contains_ci(letter, find) && !ioc_contains_ci(label, find) && !ioc_contains_ci(s1, find) &&
                !ioc_contains_ci(s2, find) && !ioc_contains_ci(remote, find)) continue;
        shown++;
        if (mode == 0) {
            char sz[24] = "-", fr[24] = "-";
            if (have_size) { human(total.QuadPart, sz, sizeof sz); human(freeb.QuadPart, fr, sizeof fr); }
            printf("    %-4s %-10s %-9s  %-8s %-20s %10s %10s  %s\n", letter, type_name(type), have ? s1 : "-", have ? fs : "-",
                   have ? label : "(no medium)", sz, fr, remote[0] ? remote : guid);
        } else if (mode == 2) {
            printf("%s,%s,%s,%s,", letter, type_name(type), s1, s2);
            csv_str(fs); putchar(',');
            csv_str(label); putchar(',');
            if (have_size) printf("%llu,%llu,", (unsigned long long)total.QuadPart, (unsigned long long)freeb.QuadPart);
            else fputs(",,", stdout);
            csv_str(guid); putchar(',');
            csv_str(remote); putchar('\n');
        } else {
            printf("%s{\"drive\":\"%s\",\"type\":\"%s\",\"mounted\":%s,\"serial\":\"%s\",\"serial_hex\":\"%s\",\"file_system\":",
                   shown > 1 ? "," : "", letter, type_name(type), have ? "true" : "false", s1, s2);
            json_str(fs);
            fputs(",\"label\":", stdout); json_str(label);
            if (have_size) printf(",\"size\":%llu,\"free\":%llu", (unsigned long long)total.QuadPart, (unsigned long long)freeb.QuadPart);
            else fputs(",\"size\":null,\"free\":null", stdout);
            fputs(",\"volume\":", stdout); json_str(guid);
            fputs(",\"remote\":", stdout); json_str(remote);
            putchar('}');
        }
    }
    SetErrorMode(oldmode);
    if (mode == 1) puts("]");
    else if (mode == 0) printf("\n%u volume(s)\n", shown);
    return 0;
}
