#ifndef WINSPECT_DETECTIONS_H
#define WINSPECT_DETECTIONS_H

// winspect detections - what Microsoft Defender has caught on this machine,
// from its Detection History files (under ProgramData, in Microsoft\Windows
// Defender\Scans\History\Service\DetectionHistory). One row per detection: time of the
// first detection (UTC), threat name, the file (with the archive it was in
// and the URL it was downloaded from, when Defender recorded them), SHA-256,
// the logged-on user, the process that touched the file, and whether and
// when it was remediated. These files remain after the event log has been
// cleared and after the quarantine has been emptied, so they answer "was
// anything found here before?" on a machine that looks clean now. Every row
// is a finding by Defender itself; the reason says whether it was remediated.
// A file or folder argument reads copies (e.g. from an image). The live
// folder needs administrator. Read-only. Usage:
//   winspect detections [<file | folder>] [--find <text>] [--json | --csv]
int cmd_detections(int argc, char **argv);

#endif
