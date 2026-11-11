#ifndef WINSPECT_OFFICE_H
#define WINSPECT_OFFICE_H

// winspect office - Microsoft Office macro trust, per user:
//   documents  every document the user clicked "Enable Editing" or "Enable
//              Content" for (Trusted Documents \ TrustRecords): path, when,
//              which application, and whether active content (macros) was
//              enabled. The usual first step of a phishing compromise leaves
//              exactly this record. Flagged when macros were enabled for a
//              mail attachment, a browser-cache / downloaded / temp-folder
//              file or a document opened from a URL.
//   settings   macro security values that weaken the defaults (VBAWarnings=1,
//              AccessVBOM=1, BlockContentExecutionFromInternet=0), user and
//              policy keys.
//   locations  trusted locations (files there skip every macro check);
//              flagged in download / temp / Public folders, on the network,
//              or when a whole drive is trusted.
// All Office versions and applications found under the key are read. Live:
// the current user; --hive reads another user's NTUSER.DAT. --flagged keeps
// only flagged rows. Read-only. Usage:
//   winspect office [--hive <NTUSER.DAT>] [--flagged] [--json | --csv]
int cmd_office(int argc, char **argv);

#endif
