// Text files of unknown encoding -> UTF-8 (see textfile.h).

#include "textfile.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Detection order as described in textfile.h.
char *read_text_file(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    unsigned char *d = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (64LL << 20) &&
            (d = (unsigned char *)malloc((size_t)sz.QuadPart + 2)) != NULL) {
        if (!ReadFile(h, d, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    if (d == NULL || got == 0) { free(d); return NULL; }
    int u16 = got >= 2 && d[0] == 0xFF && d[1] == 0xFE;
    if (!u16 && got >= 4) {
        unsigned zeros = 0, pairs = 0;
        for (DWORD i = 1; i < got && i < 512; i += 2, pairs++) if (d[i] == 0) zeros++;
        u16 = pairs && zeros * 2 > pairs;
    }
    char *out = NULL;
    if (u16) {
        const WCHAR *w = (const WCHAR *)(d + ((d[0] == 0xFF && d[1] == 0xFE) ? 2 : 0));
        int wn = (int)((got - (DWORD)((const unsigned char *)w - d)) / 2);
        int need = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
        out = (char *)malloc((size_t)need + 1);
        if (out) { WideCharToMultiByte(CP_UTF8, 0, w, wn, out, need, NULL, NULL); out[need] = 0; }
    } else if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)d, (int)got, NULL, 0) > 0) {
        out = (char *)malloc(got + 1);
        if (out) { memcpy(out, d, got); out[got] = 0; }
    } else {
        // ANSI (1252 per one write-up): widen with the legacy code page.
        int wn = MultiByteToWideChar(1252, 0, (const char *)d, (int)got, NULL, 0);
        WCHAR *w = (WCHAR *)malloc(((size_t)wn + 1) * sizeof(WCHAR));
        if (w) {
            MultiByteToWideChar(1252, 0, (const char *)d, (int)got, w, wn);
            int need = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
            out = (char *)malloc((size_t)need + 1);
            if (out) { WideCharToMultiByte(CP_UTF8, 0, w, wn, out, need, NULL, NULL); out[need] = 0; }
            free(w);
        }
    }
    free(d);
    return out;
}
