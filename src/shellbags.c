// winspect shellbags - Explorer folder-access history (ShellBags)
//
// Explorer remembers view settings for every folder a user opens and keeps
// the folder's identity as a tree of shell items:
//   <root>\BagMRU                values "0","1",... = child shell items,
//                                MRUListEx = their order, newest first
//   <root>\BagMRU\<n>            the same for the children of item n, ...
// so the path of an entry is the chain of item names from the top. Roots:
//   NTUSER.DAT    Software\Microsoft\Windows\Shell\BagMRU
//   UsrClass.dat  Local Settings\Software\Microsoft\Windows\Shell\BagMRU
//                 (live: HKCU\Software\Classes\Local Settings\...)
// Each item is decoded by the portable src/shellitem.c. Times inside items
// are DOS times (2 s resolution) taken when the bag was written; the key's
// last-write time says when that level of the tree last changed. The idea is
// the one of ShellBags Explorer / regipy; no code reused. Read-only.

#include "shellbags.h"
#include "shellitem.h"
#include "artparse.h"
#include "jsonutil.h"
#include "regsrc.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 48

typedef struct {
    regsrc *src;
    const char *hive;           // "NTUSER" / "UsrClass"
    int mode, first;
    unsigned count;
} bctx;

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

typedef struct { char name[16]; unsigned char *data; size_t len; } slot;
typedef struct { slot s[512]; int n; unsigned char mru[4096]; long mrulen; } slots;

static void on_value(const char *name, uint32_t type, const unsigned char *d, size_t len, void *vctx)
{
    slots *l = (slots *)vctx;
    if (strcmp(name, "MRUListEx") == 0 && type == REG_BINARY && d) {
        l->mrulen = (long)(len < sizeof l->mru ? len : sizeof l->mru);
        memcpy(l->mru, d, (size_t)l->mrulen);
        return;
    }
    if (type != REG_BINARY || d == NULL || name[0] < '0' || name[0] > '9' || l->n >= 512) return;
    for (const char *p = name; *p; p++) if (*p < '0' || *p > '9') return;
    slot *s = &l->s[l->n];
    s->data = (unsigned char *)malloc(len ? len : 1);
    if (s->data == NULL) return;
    memcpy(s->data, d, len);
    s->len = len;
    snprintf(s->name, sizeof s->name, "%s", name);
    l->n++;
}

static void walk(bctx *c, const char *key, const char *path, int depth)
{
    if (depth > MAX_DEPTH) return;
    rkey k;
    if (rk_open(c->src, key, &k) != 0) return;
    char when[32];
    ft_str(rk_lastwrite(c->src, &k), when, sizeof when);
    slots *l = (slots *)calloc(1, sizeof *l);
    if (l == NULL) { rk_close(&k); return; }
    rk_values(c->src, &k, on_value, l);
    rk_close(&k);
    // MRU position of each slot (newest first), -1 if not listed.
    uint32_t order[1024];
    size_t norder = l->mrulen > 0 ? mrulistex_order(l->mru, (size_t)l->mrulen, order, 1024) : 0;
    for (int i = 0; i < l->n; i++) {
        shellitem it;
        slot *s = &l->s[i];
        if (shellitem_parse(s->data, s->len, &it) <= 0) {
            snprintf(it.name, sizeof it.name, "[unreadable item]");
            it.kind = "?";
        }
        char full[4096];
        size_t pl = strlen(path);
        snprintf(full, sizeof full, "%s%s%s", path, (pl && path[pl - 1] != '\\') ? "\\" : "", it.name);
        int pos = -1;
        unsigned long slotno = strtoul(s->name, NULL, 10);
        for (size_t o = 0; o < norder; o++) if (order[o] == slotno) { pos = (int)o; break; }
        c->count++;
        if (c->mode == 0) {
            printf("  %-8s %-19s %-16s %s\n", c->hive, when, it.kind ? it.kind : "?", full);
            if (it.created[0] || it.modified[0] || it.accessed[0])
                printf("  %-8s %-19s %-16s created %s  modified %s  accessed %s\n", "", "", "",
                       it.created[0] ? it.created : "-", it.modified[0] ? it.modified : "-",
                       it.accessed[0] ? it.accessed : "-");
        } else if (c->mode == 2) {
            csv_str(c->hive); putchar(',');
            csv_str(key); putchar(',');
            printf("%s,%d,", s->name, pos);
            csv_str(when); putchar(',');
            csv_str(it.kind ? it.kind : "?"); putchar(',');
            csv_str(full); putchar(',');
            csv_str(it.created); putchar(',');
            csv_str(it.modified); putchar(',');
            csv_str(it.accessed); putchar('\n');
        } else {
            printf("%s{\"hive\":", c->first ? "" : ",");
            json_str(c->hive);
            fputs(",\"key\":", stdout);   json_str(key);
            printf(",\"slot\":%s,\"mru_position\":%d,\"key_written\":", s->name, pos);
            json_str(when);
            fputs(",\"type\":", stdout);  json_str(it.kind ? it.kind : "?");
            fputs(",\"path\":", stdout);  json_str(full);
            fputs(",\"created\":", stdout);  json_str(it.created);
            fputs(",\"modified\":", stdout); json_str(it.modified);
            fputs(",\"accessed\":", stdout); json_str(it.accessed);
            putchar('}');
            c->first = 0;
        }
        // Children of this item live in the subkey named after its slot.
        char sub[1024];
        snprintf(sub, sizeof sub, "%s\\%s", key, s->name);
        walk(c, sub, full, depth + 1);
    }
    for (int i = 0; i < l->n; i++) free(l->s[i].data);
    free(l);
}

int cmd_shellbags(int argc, char **argv)
{
    bctx c;
    memset(&c, 0, sizeof c);
    c.first = 1;
    const char *hnt = NULL, *huc = NULL;
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      c.mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  c.mode = 2;
        else if (strcmp(argv[a], "--ntuser") == 0 && a + 1 < argc)   hnt = argv[++a];
        else if (strcmp(argv[a], "--usrclass") == 0 && a + 1 < argc) huc = argv[++a];
        else {
            fprintf(stderr, "shellbags: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }
    if (c.mode == 0) {
        puts("shellbags  (folders browsed in Explorer; time = BagMRU key last write, item times are DOS times)\n");
    } else if (c.mode == 2) {
        puts("hive,key,slot,mru_position,key_written,type,path,created,modified,accessed");
    } else {
        putchar('[');
    }
    static regsrc src;
    char err[512];
    int offline = hnt || huc;
    struct { const char *file, *label, *root; } parts[2] = {
        { hnt, "NTUSER", "Software\\Microsoft\\Windows\\Shell\\BagMRU" },
        { huc, "UsrClass", "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" },
    };
    for (int i = 0; i < 2; i++) {
        if (offline) {
            if (parts[i].file == NULL) continue;
            if (regsrc_open_hive(&src, parts[i].file, err, sizeof err) != 0) {
                fprintf(stderr, "shellbags: %s\n", err);
                if (c.mode == 1) puts("]");
                return 1;
            }
            c.src = &src;
            c.hive = parts[i].label;
            walk(&c, parts[i].root, "", 0);
            regsrc_close(&src);
        } else {
            regsrc_open_live(&src, HKEY_CURRENT_USER, NULL, "HKCU");
            c.src = &src;
            c.hive = parts[i].label;
            char root[200];
            snprintf(root, sizeof root, "%s%s", i ? "Software\\Classes\\" : "", parts[i].root);
            walk(&c, root, "", 0);
            regsrc_close(&src);
        }
    }
    if (c.mode == 1) {
        puts("]");
    } else if (c.mode == 0) {
        printf("\n%u shellbag entr%s\n", c.count, c.count == 1 ? "y" : "ies");
    }
    return 0;
}
