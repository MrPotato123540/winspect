#ifndef WINSPECT_LNKPARSE_H
#define WINSPECT_LNKPARSE_H

// Portable parser for Windows Shell Link (.lnk) files, following the public
// [MS-SHLLINK] specification. Kept free of Windows headers so it can be
// unit-tested on any OS. Extracts what an analyst asks first: where does the
// shortcut point, with which arguments, from which working directory, and the
// target's timestamps as recorded when the link was made - plus, like LECmd
// shows, the volume it lived on (type, serial, label), the network share and
// the TrackerDataBlock: the NetBIOS name and MAC address of the machine where
// the link was created, which can tie a shortcut to a specific computer.

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t flags;             // LinkFlags
    uint32_t attributes;        // target FileAttributes
    uint64_t created, accessed, written;   // target FILETIMEs (0 if unknown)
    uint32_t file_size;         // target size (low 32 bits)
    char target[1024];          // LinkInfo LocalBasePath (+ suffix), else RelativePath
    char name[512];             // description (NAME_STRING)
    char relative[1024];        // RELATIVE_PATH
    char workdir[1024];         // WORKING_DIR
    char arguments[2048];       // COMMAND_LINE_ARGUMENTS
    char icon[1024];            // ICON_LOCATION
    // Where the target lived (LinkInfo VolumeID / network part):
    int has_volume;             // 1 if a VolumeID was present
    uint32_t drive_type;        // DRIVE_* (2 removable, 3 fixed, 4 remote, 5 cdrom, ...)
    uint32_t drive_serial;      // volume serial number
    char volume_label[64];
    char net_share[512];        // \\server\share for targets on a network share
    // ExtraData blocks:
    char env_target[1024];      // EnvironmentVariableDataBlock, e.g. %windir%\x.exe
    char machine_id[17];        // TrackerDataBlock: NetBIOS name of the machine the link was made on
    char mac[18];               // MAC from the file droid (UUID v1 node), "aa:bb:cc:dd:ee:ff"
    uint32_t anomalies;         // LNK_ANOM_* bits: tricks used to hide what a link runs
} lnk_info;

// A NAME / RELATIVE_PATH / WORKING_DIR count above 260 characters: the shell
// reads only 260 and continues from there, so an inflated count hides the next
// strings (typically the arguments) from naive parsers.
#define LNK_ANOM_OVERSIZED_STRING 0x1u
// Arguments or working dir contain a long run (>= 32) of blanks / CR / LF,
// which pushes the real command out of view in the Properties dialog.
#define LNK_ANOM_PADDING          0x2u

// Human-readable reason for the most serious anomaly bit set, or NULL.
const char *lnk_anomaly_reason(uint32_t anomalies);

// Name of a VolumeID drive type ("removable", "fixed", "network", ...).
const char *lnk_drive_type_name(uint32_t t);

// Returns 0 on success, -1 if this is not a shell link, -2 if truncated or
// malformed (fields parsed before the problem are kept).
int lnk_parse(const unsigned char *d, size_t n, lnk_info *out);

#endif
