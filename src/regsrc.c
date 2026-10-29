// regsrc - live registry or offline hive behind one read-only interface
// (see regsrc.h)

#include "regsrc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HIVE_MAX (1024u * 1024 * 1024)

void regsrc_u16(const unsigned char *d, size_t len, char *out, size_t n)
{
    size_t units = len / 2, w = 0;
    while (w < units && (d[2 * w] | d[2 * w + 1])) w++;
    WCHAR *tmp = (WCHAR *)malloc((w + 1) * sizeof(WCHAR));
    out[0] = '\0';
    if (tmp == NULL) return;
    for (size_t i = 0; i < w; i++) tmp[i] = (WCHAR)(d[2 * i] | (d[2 * i + 1] << 8));
    tmp[w] = 0;
    if (n > 0 && WideCharToMultiByte(CP_UTF8, 0, tmp, -1, out, (int)n, NULL, NULL) == 0) out[0] = '\0';
    free(tmp);
}

static void to_wide(const char *s, WCHAR *w, int n)
{
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) == 0) w[0] = 0;
}

LONG regsrc_open_live(regsrc *s, HKEY root, const char *sub, const char *label)
{
    memset(s, 0, sizeof *s);
    snprintf(s->label, sizeof s->label, "%s", label);
    if (sub == NULL || sub[0] == '\0') {
        s->live = root;
        return 0;
    }
    WCHAR w[512];
    to_wide(sub, w, 512);
    return RegOpenKeyExW(root, w, 0, KEY_READ | KEY_WOW64_64KEY, &s->live);
}

int regsrc_open_hive(regsrc *s, const char *path, char *err, size_t errn)
{
    memset(s, 0, sizeof *s);
    s->is_hive = 1;
    snprintf(s->label, sizeof s->label, "%s", path);
    WCHAR w[MAX_PATH * 2];
    to_wide(path, w, MAX_PATH * 2);
    HANDLE f = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        snprintf(err, errn, "cannot open %s (%s)", path,
                 e == ERROR_SHARING_VIOLATION ? "in use by Windows - this is a LOADED hive; copy it "
                                                "with a backup/VSS tool or use the live mode"
                 : e == ERROR_ACCESS_DENIED ? "access denied" : "not found / unreadable");
        return -1;
    }
    LARGE_INTEGER sz;
    DWORD got = 0;
    int ok = GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart <= HIVE_MAX &&
             (s->buf = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL &&
             ReadFile(f, s->buf, (DWORD)sz.QuadPart, &got, NULL) && got == (DWORD)sz.QuadPart;
    CloseHandle(f);
    if (!ok) {
        snprintf(err, errn, "cannot read %s", path);
        free(s->buf);
        s->buf = NULL;
        return -1;
    }
    int rc = regf_open(&s->h, s->buf, got);
    if (rc != 0) {
        snprintf(err, errn, "%s is %s", path, rc == -1 ? "not a registry hive (no regf header)"
                                                       : "a damaged / truncated hive");
        free(s->buf);
        s->buf = NULL;
        return -1;
    }
    return 0;
}

int regsrc_dirty(const regsrc *s)
{
    return s->is_hive && s->h.seq1 != s->h.seq2;
}

void regsrc_close(regsrc *s)
{
    if (s->is_hive) {
        free(s->buf);
        s->buf = NULL;
    } else if (s->live != NULL && s->live != HKEY_CURRENT_USER && s->live != HKEY_LOCAL_MACHINE &&
               s->live != HKEY_USERS) {
        RegCloseKey(s->live);
    }
}

int rk_open(regsrc *s, const char *path, rkey *k)
{
    memset(k, 0, sizeof *k);
    if (s->is_hive) {
        if (regf_find(&s->h, path, &k->cell) != 0) return -1;
        k->open = 1;
        return 0;
    }
    WCHAR w[1024];
    to_wide(path, w, 1024);
    LONG r = RegOpenKeyExW(s->live, w, 0, KEY_READ | KEY_WOW64_64KEY, &k->hk);
    if (r != ERROR_SUCCESS) return (int)r;
    k->open = 1;
    return 0;
}

void rk_close(rkey *k)
{
    if (k->open && k->hk != NULL) RegCloseKey(k->hk);
    k->open = 0;
}

uint64_t rk_lastwrite(regsrc *s, const rkey *k)
{
    if (s->is_hive) {
        regf_key_info ki;
        return regf_key(&s->h, k->cell, &ki) == 0 ? ki.last_written : 0;
    }
    FILETIME ft;
    if (RegQueryInfoKeyW(k->hk, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ft) != ERROR_SUCCESS)
        return 0;
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

struct sub_fwd { regsrc *s; rk_name_cb cb; void *ctx; };
static void sub_cb(uint32_t cell, void *vctx)
{
    struct sub_fwd *f = (struct sub_fwd *)vctx;
    regf_key_info ki;
    if (regf_key(&f->s->h, cell, &ki) == 0) f->cb(ki.name, f->ctx);
}

int rk_subkeys(regsrc *s, const rkey *k, rk_name_cb cb, void *ctx)
{
    if (s->is_hive) {
        struct sub_fwd f = { s, cb, ctx };
        return regf_subkeys(&s->h, k->cell, sub_cb, &f);
    }
    int n = 0;
    for (DWORD i = 0;; i++) {
        WCHAR name[256];
        DWORD nl = 256;
        LONG r = RegEnumKeyExW(k->hk, i, name, &nl, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        char u[768];
        WideCharToMultiByte(CP_UTF8, 0, name, -1, u, sizeof u, NULL, NULL);
        cb(u, ctx);
        n++;
    }
    return n;
}

struct val_fwd { rk_value_cb cb; void *ctx; };
static void val_cb(const regf_value *v, void *vctx)
{
    struct val_fwd *f = (struct val_fwd *)vctx;
    f->cb(v->name, v->type, v->data, v->len, f->ctx);
}

int rk_values(regsrc *s, const rkey *k, rk_value_cb cb, void *ctx)
{
    if (s->is_hive) {
        struct val_fwd f = { cb, ctx };
        return regf_values(&s->h, k->cell, val_cb, &f);
    }
    DWORD maxname = 0, maxdata = 0;
    if (RegQueryInfoKeyW(k->hk, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &maxname, &maxdata, NULL, NULL)
            != ERROR_SUCCESS) return -1;
    WCHAR *name = (WCHAR *)malloc((maxname + 2) * sizeof(WCHAR));
    BYTE *data = (BYTE *)malloc(maxdata + 2);
    int n = 0;
    for (DWORD i = 0; name != NULL && data != NULL; i++) {
        DWORD nl = maxname + 1, dl = maxdata, type = 0;
        LONG r = RegEnumValueW(k->hk, i, name, &nl, NULL, &type, data, &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;      // grew meanwhile: skip, never truncate silently
        char u[1024];
        WideCharToMultiByte(CP_UTF8, 0, name, -1, u, sizeof u, NULL, NULL);
        cb(u, type, data, dl, ctx);
        n++;
    }
    free(name);
    free(data);
    return n;
}

struct get_fwd { const char *name; uint32_t *type; unsigned char *out; size_t n; long len; };
static void get_cb(const char *name, uint32_t type, const unsigned char *data, size_t len, void *vctx)
{
    struct get_fwd *g = (struct get_fwd *)vctx;
    if (g->len >= 0 || _stricmp(name, g->name) != 0) return;
    if (g->type) *g->type = type;
    size_t take = len < g->n ? len : g->n;
    if (take && data) memcpy(g->out, data, take);
    g->len = (long)len;
}

long rk_get(regsrc *s, const rkey *k, const char *name, uint32_t *type, unsigned char *out, size_t n)
{
    struct get_fwd g = { name, type, out, n, -1 };
    rk_values(s, k, get_cb, &g);
    return g.len;
}

int rk_exists(regsrc *s, const rkey *k, const char *name)
{
    if (s->is_hive) {
        return rk_get(s, k, name, NULL, NULL, 0) >= 0;      // n = 0: nothing copied
    }
    WCHAR w[512];
    to_wide(name, w, 512);
    return RegQueryValueExW(k->hk, w, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
}

int rk_get_str(regsrc *s, const rkey *k, const char *name, char *out, size_t n)
{
    unsigned char buf[4096];
    uint32_t type = 0;
    out[0] = '\0';
    long len = rk_get(s, k, name, &type, buf, sizeof buf);
    if (len < 0 || (type != REG_SZ && type != REG_EXPAND_SZ)) return 0;
    regsrc_u16(buf, (size_t)len < sizeof buf ? (size_t)len : sizeof buf, out, n);
    return 1;
}

void regsrc_control_set(regsrc *s, char *out, size_t n)
{
    snprintf(out, n, "CurrentControlSet");
    if (!s->is_hive) return;
    rkey sel;
    if (rk_open(s, "Select", &sel) != 0) {
        snprintf(out, n, "ControlSet001");
        return;
    }
    unsigned char d[4];
    uint32_t type = 0;
    long len = rk_get(s, &sel, "Current", &type, d, sizeof d);
    unsigned cur = (len == 4 && type == REG_DWORD) ? (unsigned)(d[0] | (d[1] << 8) | (d[2] << 16) | ((unsigned)d[3] << 24)) : 1;
    if (cur == 0 || cur > 999) cur = 1;
    snprintf(out, n, "ControlSet%03u", cur);
    rk_close(&sel);
}
