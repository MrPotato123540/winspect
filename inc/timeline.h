#ifndef WINSPECT_TIMELINE_H
#define WINSPECT_TIMELINE_H

// winspect timeline - one time-ordered view of what the evidence commands
// already know: program runs (prefetch, bam, userassist), files opened and
// folders browsed (jumplist, lnk, shellbags), deletions (recyclebin), USB
// devices, RDP connections, Run-box entries, PowerShell history, logons and
// password changes (users), BITS jobs, scheduled task registrations,
// per-user COM registrations, high-signal events, logon sessions (logons),
// Defender detections and remediations (detections),
// crash reports (wer), Office documents the user trusted (office), Windows install / last
// shutdown / profile loads (sysinfo). Each source command is
// run with --json and its timestamps become rows (UTC, newest first); a row
// keeps the source's "suspicious" mark. Per-user sources read the CURRENT
// user. --root <folder> builds the same timeline from an offline Windows
// installation (a mounted image): its hives, Prefetch, Amcache, Recycle Bin,
// tasks, event logs and every user profile, each row naming its user.
// --since keeps the last <hours>, or everything from a UTC date (YYYY-MM-DD); --sources picks a comma-separated subset.
// Read-only (it only calls read-only commands). Usage:
//   winspect timeline [--root <folder>] [--since <hours | YYYY-MM-DD>] [--sources a,b,...] [--flagged] [--json | --csv]
int cmd_timeline(int argc, char **argv);

#endif
