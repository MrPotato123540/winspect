#ifndef WINSPECT_ACTIVITIES_H
#define WINSPECT_ACTIVITIES_H

// winspect activities - Windows 10 Timeline (ActivitiesCache.db under
// %LOCALAPPDATA%\ConnectedDevicesPlatform\<account>\): which application was
// used when and for how long, and the documents it opened, read with
// winspect's own SQLite reader. Rows: start / end time, the application (exe
// path or app id), activity type (opened, in focus...), what was shown
// (document, page) and the focus duration. Flags applications run from
// user-writable folders. Default: the current user; --home reads one user
// folder (e.g. in a mounted image); a file argument reads a copied
// database. Windows 11 no longer records new activity. Read-only. Usage:
//   winspect activities [<ActivitiesCache.db> | --home <user folder>] [--flagged] [--json | --csv]
int cmd_activities(int argc, char **argv);

#endif
