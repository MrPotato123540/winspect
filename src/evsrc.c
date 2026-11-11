// Event sources: live channel or .evtx file, both delivered as XML text.
// (events.c predates this module and keeps its own copy of the query loop.)

#include "evsrc.h"
#include "evtx.h"

#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DWORD evsrc_live(const char *channel, const char *xpath, unsigned max, evsrc_cb cb, void *ctx)
{
    WCHAR wpath[256], wxpath[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, channel, -1, wpath, 256) == 0 ||
            MultiByteToWideChar(CP_UTF8, 0, xpath, -1, wxpath, 1024) == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    EVT_HANDLE q = EvtQuery(NULL, wpath, wxpath, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (q == NULL) {
        return GetLastError();
    }
    unsigned total = 0;
    WCHAR *wxml = NULL;
    DWORD wcap = 0;                         // bytes
    while (total < max) {
        EVT_HANDLE ev[32];
        DWORD got = 0;
        if (!EvtNext(q, 32, ev, 5000, 0, &got)) {
            break;                          // ERROR_NO_MORE_ITEMS or timeout
        }
        for (DWORD i = 0; i < got; i++) {
            if (total < max) {
                DWORD used = 0, props = 0;
                BOOL ok = EvtRender(NULL, ev[i], EvtRenderEventXml, wcap, wxml, &used, &props);
                if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    // used is a byte count; keep whole WCHARs and room to grow.
                    DWORD bytes = ((used + 1) / (DWORD)sizeof(WCHAR) + 64) * (DWORD)sizeof(WCHAR);
                    WCHAR *nb = (WCHAR *)realloc(wxml, bytes);
                    if (nb != NULL) {
                        wxml = nb;
                        wcap = bytes;
                        ok = EvtRender(NULL, ev[i], EvtRenderEventXml, wcap, wxml, &used, &props);
                    }
                }
                if (ok && wxml != NULL && used > 0) {
                    int need = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
                    char *xml = need > 0 ? (char *)malloc((size_t)need) : NULL;
                    if (xml != NULL) {
                        WideCharToMultiByte(CP_UTF8, 0, wxml, -1, xml, need, NULL, NULL);
                        cb(xml, ctx);
                        free(xml);
                        total++;
                    }
                }
            }
            EvtClose(ev[i]);
        }
    }
    free(wxml);
    EvtClose(q);
    return 0;
}

typedef struct { evsrc_cb cb; void *ctx; } fwd;

static void forward(uint64_t id, uint64_t written, const char *xml, void *vctx)
{
    (void)id; (void)written;
    fwd *f = (fwd *)vctx;
    f->cb(xml, f->ctx);
}

int evsrc_file(const char *path, evsrc_cb cb, void *ctx, int *dirty)
{
    if (dirty) *dirty = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 1;
    }
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1LL << 31) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart)) != NULL) {
        if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    evtx_file f;
    if (d == NULL || evtx_open(&f, d, got) != 0) {
        free(d);
        return 2;
    }
    if (dirty) *dirty = f.dirty;
    fwd w = { cb, ctx };
    evtx_records(&f, forward, &w);
    free(d);
    return 0;
}
