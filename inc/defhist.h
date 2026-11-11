#ifndef WINSPECT_DEFHIST_H
#define WINSPECT_DEFHIST_H

// Microsoft Defender "Detection History" files: one small binary file per
// detection under
//   ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<nn>\<GUID>
// They outlive a cleared event log and a deleted quarantine. Portable,
// unit-tested; layout from public write-ups of the format and from looking
// at real files (no code reused):
//   the whole file is a sequence of values, each
//       u32 size | u32 type | <size> bytes | padding to a multiple of 8
//   types seen: 0x15 UTF-16 string, 0x06 / 0x05 u32, 0x08 u64, 0x0A FILETIME,
//               0x1E GUID, 0x28 blob
//   order: threat id (u64), detection GUID, "Magic.Version:1.2", threat name,
//          counters, then per resource: "Magic.Version:1.2", resource type
//          ("file", "containerfile", "webfile", "regkey" ...), location, two
//          u32 and a blob of named properties (ThreatTrackingSha256 ...);
//          then the tail: time of the last status change, a GUID, the user,
//          the process that touched the file ("Unknown" when none), the time
//          of the first detection, the remediation time (0 = none) and the
//          account that remediated.
// Every size is checked against the buffer; an unknown type is skipped by
// its size, never interpreted.

#include <stddef.h>
#include <stdint.h>

#define DH_MAX_RES 8

typedef struct {
    char type[32];              // "file", "containerfile", "webfile" ...
    char location[1024];        // path; for webfile "path|url|pid:..."
    char sha256[65];            // from the property blob, "" if absent
} dh_resource;

typedef struct {
    uint64_t threat_id;
    char guid[40];              // detection id, the file's own name
    char threat[200];           // "Trojan:Win32/..."
    dh_resource res[DH_MAX_RES];
    int nres;                   // resources kept (at most DH_MAX_RES)
    uint64_t status_time;       // FILETIME of the last threat status change
    uint64_t detect_time;       // FILETIME of the first detection
    uint64_t remediation_time;  // 0 = not remediated
    char user[200];             // DOMAIN\user that was logged on
    char process[520];          // "" when Defender logged "Unknown"
    char remediation_user[200];
} dh_record;

// Returns 0, or -1 when the buffer is not a detection history file (no
// "Magic.Version" marker followed by a threat name).
int dh_parse(const unsigned char *d, size_t n, dh_record *r);

// The resource to show first: the first of type "file", else the first.
const dh_resource *dh_primary(const dh_record *r);

// From a "webfile" location ("path|url|pid:..."): the URL part, "" if none.
void dh_web_url(const char *location, char *out, size_t n);

#endif
