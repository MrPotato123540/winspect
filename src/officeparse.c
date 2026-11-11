// Office security artifacts (see officeparse.h). Portable C.

#include "officeparse.h"
#include "ioc.h"

#include <stdio.h>
#include <string.h>

int trustrec_parse(const unsigned char *d, size_t n, uint64_t *filetime, int *content_enabled)
{
    *filetime = 0;
    *content_enabled = 0;
    if (n < 24) return -1;
    uint64_t ft = 0;
    for (int i = 7; i >= 0; i--) ft = ft << 8 | d[i];
    *filetime = ft;
    uint32_t flags = (uint32_t)d[20] | (uint32_t)d[21] << 8 | (uint32_t)d[22] << 16 | (uint32_t)d[23] << 24;
    *content_enabled = flags == 0x7FFFFFFFu;
    return 0;
}

void trustrec_path(const char *name, char *out, size_t n)
{
    snprintf(out, n, "%s", name);
    if (strstr(out, "://") != NULL) return;
    for (char *p = out; *p; p++) if (*p == '/') *p = '\\';
}

static int is_remote(const char *p)
{
    return strstr(p, "://") != NULL || (p[0] == '\\' && p[1] == '\\');
}

const char *trustrec_reason(const char *path, int content_enabled)
{
    if (!content_enabled) return NULL;
    // Outlook opens attachments from this cache: the document arrived by mail.
    if (ioc_contains_ci(path, "\\Content.Outlook\\")) return "macros enabled for a mail attachment";
    if (ioc_contains_ci(path, "\\INetCache\\") || ioc_contains_ci(path, "\\Temporary Internet Files\\"))
        return "macros enabled for a file opened from the browser cache";
    if (strstr(path, "://") != NULL) return "macros enabled for a document opened from a URL";
    if (ioc_contains_ci(path, "\\Downloads\\")) return "macros enabled for a downloaded document";
    if (ioc_contains_ci(path, "\\Temp\\") || ioc_contains_ci(path, "%TEMP%") || ioc_contains_ci(path, "%TMP%"))
        return "macros enabled for a document in a temp folder (opened from an archive?)";
    return NULL;
}

const char *office_setting_reason(const char *name, uint32_t value)
{
    if (ioc_contains_ci(name, "VBAWarnings") && strlen(name) == 11 && value == 1)
        return "all macros run without notification (VBAWarnings=1)";
    if (ioc_contains_ci(name, "AccessVBOM") && strlen(name) == 10 && value == 1)
        return "programmatic access to the VBA project is allowed (AccessVBOM=1)";
    if (ioc_contains_ci(name, "BlockContentExecutionFromInternet") && strlen(name) == 33 && value == 0)
        return "macros in files from the internet are not blocked (policy set to 0)";
    return NULL;
}

// 1 when dir ("\\Temp") is a whole path component of p: followed by a
// backslash or the end. "\\Templates" must not count as "\\Temp".
static int has_dir(const char *p, const char *dir)
{
    size_t dl = strlen(dir);
    for (; *p; p++) {
        size_t i = 0;
        while (i < dl && p[i] && (p[i] | 0x20) == (dir[i] | 0x20)) i++;
        if (i == dl && (p[dl] == '\\' || p[dl] == '\0')) return 1;
    }
    return 0;
}

const char *trustloc_reason(const char *path)
{
    if (path[0] == '\0') return NULL;
    char p[1024];
    trustrec_path(path, p, sizeof p);
    if (is_remote(p)) return "trusted location on the network / at a URL";
    if (has_dir(p, "\\Downloads")) return "trusted location in a download folder";
    if (has_dir(p, "\\Temp") || has_dir(p, "\\Tmp") || ioc_contains_ci(p, "%TEMP%") || ioc_contains_ci(p, "%TMP%"))
        return "trusted location in a temp folder";
    if (has_dir(p, "\\Users\\Public") || ioc_contains_ci(p, "%PUBLIC%")) return "trusted location in the Public profile";
    // A whole drive or profile root: everything below is trusted.
    size_t L = strlen(p);
    if ((L == 2 || L == 3) && p[1] == ':') return "a whole drive is a trusted location";
    return NULL;
}
