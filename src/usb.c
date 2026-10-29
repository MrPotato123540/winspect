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
// Precise times (Windows 8+) are device properties under the instance key:
//   Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064  install date
//                                                    \0065  first install date
//                                                    \0066  last arrival (plugged in)
//                                                    \0067  last removal
// each a DEVPROP_TYPE_FILETIME (registry type 0xFFFF0010, 8 bytes) - the
// DEVPKEY_Device_* property ids 100..103. The Properties key is readable only
// by SYSTEM on a live machine, so live runs usually show "-"; an offline
// SYSTEM hive (--hive) has no such restriction. Also shown: the disk's
// partition-manager DiskId (Device Parameters\Partmgr) and any drive letter
// whose MountedDevices entry names this device's serial.
//
// The instance key's last-write time is NOT a reliable "last plugged in"
// time (driver/property updates touch it); it is shown as a hint only.
//
// Read-only (live registry or an in-memory copy of a hive file).

#include "usb.h"
#include "jsonutil.h"
#include "ioc.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVPROP_GUID "{83da6326-97a6-4088-9453-a1923f573b29}"

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

static void ft_str(uint64_t t, char *out, size_t n)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    if (t == 0 || !FileTimeToSystemTime(&ft, &st)) { snprintf(out, n, "-"); return; }
    snprintf(out, n, "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

// MountedDevices values whose data is a device path (UTF-16 text such as
// "\??\USBSTOR#Disk&Ven_X&Prod_Y#SERIAL&0#{53f56307-...}") - kept so each
// device can be matched to the drive letters / volumes that pointed at it.
typedef struct { char name[128]; char target[512]; } mount;
typedef struct { mount m[256]; int n; } mounts;

static void on_mount(const char *name, uint32_t type, const unsigned char *d, size_t len, void *vctx)
{
    mounts *ms = (mounts *)vctx;
    (void)type;
    // Text targets start with "\??\" or "_??_" in UTF-16; binary ones are
    // 12-byte MBR signature+offset or "DMIO:ID:" + GPT GUID - not a device path.
    if (ms->n >= 256 || d == NULL || len < 8 || d[1] != 0 || (d[0] != '\\' && d[0] != '_')) return;
    mount *m = &ms->m[ms->n++];
    snprintf(m->name, sizeof m->name, "%s", name);
    regsrc_u16(d, len, m->target, sizeof m->target);
}

typedef struct {
    regsrc *src;
    mounts *ms;
    int mode, first, props_denied;
    unsigned count;
    char base[256];             // <control set>\Enum\USBSTOR
    char devid[512];
} uctx;

static uint64_t devprop_time(uctx *c, const char *inst_path, const char *pid)
{
    char p[900];
    snprintf(p, sizeof p, "%s\\Properties\\" DEVPROP_GUID "\\%s", inst_path, pid);
    rkey k;
    int r = rk_open(c->src, p, &k);
    if (r != 0) {
        if (r == ERROR_ACCESS_DENIED) c->props_denied = 1;
        return 0;
    }
    unsigned char d[8];
    uint32_t type = 0;
    uint64_t t = 0;
    if (rk_get(c->src, &k, "", &type, d, sizeof d) == 8 && (type & 0xFFFF) == 0x10) {
        for (int i = 7; i >= 0; i--) t = (t << 8) | d[i];
    }
    rk_close(&k);
    return t;
}

static void on_instance(const char *serial, void *vctx)
{
    uctx *c = (uctx *)vctx;
    char inst[900];
    snprintf(inst, sizeof inst, "%s\\%s\\%s", c->base, c->devid, serial);
    rkey k;
    if (rk_open(c->src, inst, &k) != 0) return;
    char vendor[128], product[128], rev[64], fname[512], container[64] = "", diskid[64] = "";
    id_field(c->devid, "Ven_", vendor, sizeof vendor);
    id_field(c->devid, "Prod_", product, sizeof product);
    id_field(c->devid, "Rev_", rev, sizeof rev);
    rk_get_str(c->src, &k, "FriendlyName", fname, sizeof fname);
    rk_get_str(c->src, &k, "ContainerID", container, sizeof container);
    uint64_t lw = rk_lastwrite(c->src, &k);
    rk_close(&k);
    char pm[960];
    snprintf(pm, sizeof pm, "%s\\Device Parameters\\Partmgr", inst);
    if (rk_open(c->src, pm, &k) == 0) {
        rk_get_str(c->src, &k, "DiskId", diskid, sizeof diskid);
        rk_close(&k);
    }
    // Windows-generated ids look like "7&2a5c3f1&0": '&' in position 1.
    int generated = (serial[0] != '\0' && serial[1] == '&');
    uint64_t t[4];
    static const char *const pid[4] = { "0064", "0065", "0066", "0067" };
    for (int i = 0; i < 4; i++) t[i] = devprop_time(c, inst, pid[i]);
    char ts[4][32], lws[32];
    for (int i = 0; i < 4; i++) ft_str(t[i], ts[i], sizeof ts[i]);
    ft_str(lw, lws, sizeof lws);

    // Drive letters / volumes whose MountedDevices target names this serial.
    char letters[256] = "";
    size_t ll = 0;
    char needle[300];
    snprintf(needle, sizeof needle, "#%s#", serial);
    for (int i = 0; i < c->ms->n; i++) {
        if (!ioc_contains_ci(c->ms->m[i].target, needle)) continue;
        const char *nm = c->ms->m[i].name;
        if (strncmp(nm, "\\DosDevices\\", 12) == 0) nm += 12;
        int w = snprintf(letters + ll, sizeof letters - ll, "%s%s", ll ? ", " : "", nm);
        if (w > 0 && (size_t)w < sizeof letters - ll) ll += (size_t)w;
    }

    c->count++;
    if (c->mode == 0) {
        printf("  %s\n", fname[0] ? fname : c->devid);
        printf("      vendor %-12s product %-20s rev %s\n", vendor, product, rev);
        printf("      serial %s%s\n", serial, generated ? "   (generated by Windows - device has no serial)" : "");
        printf("      first installed %s   last plugged in %s   last removed %s\n", ts[1], ts[2], ts[3]);
        if (diskid[0])  printf("      disk id %s\n", diskid);
        if (letters[0]) printf("      mounted as %s\n", letters);
        printf("      key last written %s UTC (hint only)\n\n", lws);
    } else if (c->mode == 2) {
        csv_str(vendor);  putchar(',');
        csv_str(product); putchar(',');
        csv_str(rev);     putchar(',');
        csv_str(serial);  putchar(',');
        fputs(generated ? "true," : "false,", stdout);
        csv_str(fname);   putchar(',');
        csv_str(ts[0]); putchar(','); csv_str(ts[1]); putchar(',');
        csv_str(ts[2]); putchar(','); csv_str(ts[3]); putchar(',');
        csv_str(diskid);  putchar(',');
        csv_str(letters); putchar(',');
        csv_str(lws);     putchar('\n');
    } else {
        printf("%s{\"vendor\":", c->first ? "" : ",");
        json_str(vendor);
        fputs(",\"product\":", stdout);  json_str(product);
        fputs(",\"revision\":", stdout); json_str(rev);
        fputs(",\"serial\":", stdout);   json_str(serial);
        printf(",\"generated_serial\":%s,\"friendly_name\":", generated ? "true" : "false");
        json_str(fname);
        static const char *const keys[4] = { "installed", "first_installed", "last_connected", "last_removed" };
        for (int i = 0; i < 4; i++) {
            printf(",\"%s\":", keys[i]);
            if (t[i]) json_str(ts[i]); else fputs("null", stdout);
        }
        fputs(",\"container_id\":", stdout); json_str(container);
        fputs(",\"disk_id\":", stdout);      json_str(diskid);
        fputs(",\"mounted_as\":", stdout);   json_str(letters);
        fputs(",\"key_last_write\":", stdout); json_str(lws);
        putchar('}');
        c->first = 0;
    }
}

typedef struct { char ids[256][256]; int n; } idlist;
static void on_name(const char *name, void *vctx)
{
    idlist *l = (idlist *)vctx;
    if (l->n < 256) snprintf(l->ids[l->n++], sizeof l->ids[0], "%s", name);
}

int cmd_usb(int argc, char **argv)
{
    uctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *hive = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--hive") == 0 && a + 1 < argc) hive = argv[++a];
        else {
            fprintf(stderr, "usb: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    static const char *HDR = "vendor,product,revision,serial,generated_serial,friendly_name,installed,"
                             "first_installed,last_connected,last_removed,disk_id,mounted_as,key_last_write";

    regsrc src;
    if (hive != NULL) {
        char err[512];
        if (regsrc_open_hive(&src, hive, err, sizeof err) != 0) {
            fprintf(stderr, "usb: %s\n", err);
            return 1;
        }
        if (regsrc_dirty(&src)) fputs("usb: note: hive is dirty (transaction logs not replayed)\n", stderr);
    } else if (regsrc_open_live(&src, HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM") != ERROR_SUCCESS) {
        fputs("usb: cannot open HKLM\\SYSTEM\n", stderr);
        return 1;
    }
    c.src = &src;
    char cs[32];
    regsrc_control_set(&src, cs, sizeof cs);
    snprintf(c.base, sizeof c.base, "%s\\Enum\\USBSTOR", cs);

    static mounts ms;
    ms.n = 0;
    c.ms = &ms;
    rkey k;
    if (rk_open(&src, "MountedDevices", &k) == 0) {
        rk_values(&src, &k, on_mount, &ms);
        rk_close(&k);
    }

    int r = rk_open(&src, c.base, &k);
    if (r != 0) {
        regsrc_close(&src);
        if (r == -1 || r == ERROR_FILE_NOT_FOUND) {
            // No USB storage was ever attached (or the key was cleaned).
            if (c.mode == 1)      puts("[]");
            else if (c.mode == 2) puts(HDR);
            else                  puts("usb: no USBSTOR devices recorded");
            return 0;
        }
        fprintf(stderr, "usb: cannot open USBSTOR key (error %d)\n", r);
        return 1;
    }
    static idlist devs;
    devs.n = 0;
    rk_subkeys(&src, &k, on_name, &devs);
    rk_close(&k);

    if (c.mode == 0) {
        printf("usb storage history (Enum\\USBSTOR in %s)\n\n", src.label);
    } else if (c.mode == 2) {
        puts(HDR);
    } else {
        putchar('[');
    }
    for (int d = 0; d < devs.n; d++) {
        snprintf(c.devid, sizeof c.devid, "%s", devs.ids[d]);
        char p[800];
        snprintf(p, sizeof p, "%s\\%s", c.base, c.devid);
        if (rk_open(&src, p, &k) != 0) continue;
        static idlist inst;
        inst.n = 0;
        rk_subkeys(&src, &k, on_name, &inst);
        rk_close(&k);
        for (int i = 0; i < inst.n; i++) on_instance(inst.ids[i], &c);
    }
    regsrc_close(&src);

    if (c.mode == 0) {
        printf("%u device instance(s)\n", c.count);
        if (c.props_denied)
            puts("note: plug-in/removal times are device properties only SYSTEM can read on a live\n"
                 "      machine; run on a copy of the SYSTEM hive with --hive to see them.");
    } else if (c.mode == 1) {
        puts("]");
    }
    return 0;
}
