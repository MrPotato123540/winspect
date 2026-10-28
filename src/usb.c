// winspect usb - USB storage history from the PnP enumeration tree
//
// When a USB mass-storage device is first attached, the PnP manager creates
//   HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<device id>\<instance id>
// The device id has the form  Disk&Ven_<vendor>&Prod_<product>&Rev_<rev>  and
// the instance id is the device's serial number (with "&0" etc. appended). If
// the device has no usable serial, Windows makes one up - those ids have '&' as
// their SECOND character, so we flag them as "generated". The instance key
// holds FriendlyName ("SanDisk Cruzer USB Device"). The entries stay after the
// device is removed, which is what makes this a forensic artifact.
//
// The key's last-write time is NOT a reliable "last plugged in" timestamp (any
// driver/property update touches it), so we label it as a hint only. The
// precise arrival/removal times live under the Properties subkey, which only
// SYSTEM can read - out of scope for a user-mode, no-privilege tool.
//
// Read-only: KEY_READ only.

#include "usb.h"
#include "jsonutil.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define USBSTOR_KEY L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"

static void w2u(const WCHAR *w, char *out, int n)
{
    int got = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
    if (got <= 0) {
        out[0] = '\0';
    }
}

// Copy the text after "<tag>" up to the next '&' (or end) out of a device id
// such as "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00".
static void id_field(const char *id, const char *tag, char *out, size_t n)
{
    out[0] = '\0';
    const char *p = strstr(id, tag);
    if (p == NULL) {
        return;
    }
    p += strlen(tag);
    size_t i = 0;
    while (p[i] != '\0' && p[i] != '&' && i + 1 < n) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

int cmd_usb(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "usb: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    HKEY root;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, USBSTOR_KEY, 0, KEY_READ, &root);
    if (rc == ERROR_FILE_NOT_FOUND) {
        // No USB storage was ever attached (or the key was cleaned).
        if (mode == 1)      puts("[]");
        else if (mode == 2) puts("vendor,product,revision,serial,generated_serial,friendly_name,key_last_write");
        else                puts("usb: no USBSTOR devices recorded");
        return 0;
    }
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "usb: cannot open USBSTOR key (error %ld)\n", (long)rc);
        return 1;
    }

    if (mode == 0) {
        puts("usb storage history (Enum\\USBSTOR)\n");
    } else if (mode == 2) {
        puts("vendor,product,revision,serial,generated_serial,friendly_name,key_last_write");
    } else {
        putchar('[');
    }

    unsigned count = 0;
    int first = 1;
    for (DWORD d = 0;; d++) {
        WCHAR wdev[256];
        DWORD dl = 256;
        if (RegEnumKeyExW(root, d, wdev, &dl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        HKEY dev;
        if (RegOpenKeyExW(root, wdev, 0, KEY_READ, &dev) != ERROR_SUCCESS) {
            continue;
        }
        char devid[512], vendor[128], product[128], rev[64];
        w2u(wdev, devid, sizeof devid);
        id_field(devid, "Ven_", vendor, sizeof vendor);
        id_field(devid, "Prod_", product, sizeof product);
        id_field(devid, "Rev_", rev, sizeof rev);

        for (DWORD s = 0;; s++) {
            WCHAR winst[256];
            DWORD il = 256;
            FILETIME ft = { 0, 0 };
            if (RegEnumKeyExW(dev, s, winst, &il, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) {
                break;
            }
            char serial[512];
            w2u(winst, serial, sizeof serial);
            // Windows-generated ids look like "7&2a5c3f1&0": '&' in position 1.
            int generated = (serial[0] != '\0' && serial[1] == '&');

            // FriendlyName (REG_SZ). RegGetValueW guarantees NUL termination.
            WCHAR wfn[256];
            DWORD fl = sizeof wfn;
            char fname[512] = "";
            if (RegGetValueW(dev, winst, L"FriendlyName", RRF_RT_REG_SZ, NULL, wfn, &fl)
                    == ERROR_SUCCESS) {
                w2u(wfn, fname, sizeof fname);
            }

            SYSTEMTIME st;
            char when[32] = "";
            if (FileTimeToSystemTime(&ft, &st)) {
                snprintf(when, sizeof when, "%04u-%02u-%02u %02u:%02u:%02u",
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            }

            count++;
            if (mode == 0) {
                printf("  %s\n", fname[0] ? fname : devid);
                printf("      vendor %-12s product %-20s rev %s\n", vendor, product, rev);
                printf("      serial %s%s\n", serial, generated ? "   (generated by Windows - device has no serial)" : "");
                printf("      key last written %s UTC (hint, not exact plug-in time)\n\n", when);
            } else if (mode == 2) {
                csv_str(vendor);  putchar(',');
                csv_str(product); putchar(',');
                csv_str(rev);     putchar(',');
                csv_str(serial);  putchar(',');
                fputs(generated ? "true," : "false,", stdout);
                csv_str(fname);   putchar(',');
                csv_str(when);    putchar('\n');
            } else {
                printf("%s{\"vendor\":", first ? "" : ",");
                json_str(vendor);
                fputs(",\"product\":", stdout);  json_str(product);
                fputs(",\"revision\":", stdout); json_str(rev);
                fputs(",\"serial\":", stdout);   json_str(serial);
                printf(",\"generated_serial\":%s,\"friendly_name\":", generated ? "true" : "false");
                json_str(fname);
                fputs(",\"key_last_write\":", stdout); json_str(when);
                putchar('}');
                first = 0;
            }
        }
        RegCloseKey(dev);
    }
    RegCloseKey(root);

    if (mode == 0) {
        printf("%u device instance(s)\n", count);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
