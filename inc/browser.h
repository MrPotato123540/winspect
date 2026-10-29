#ifndef WINSPECT_BROWSER_H
#define WINSPECT_BROWSER_H

// winspect browser - web history and downloads from Chrome, Edge, Brave
// (Chromium "History" databases, every profile) and Firefox (places.sqlite
// with its -wal file), read with winspect's own SQLite reader: visited URLs
// with title, visit count and last visit time, and downloads with source
// URL, saved path, size and the browser's own danger verdict. Flags
// downloads the browser warned about (or that the user kept anyway),
// downloads from a bare IP address, downloaded programs/scripts and visits
// to bare IP addresses. Default: the current user; --all-users reads every
// profile under C:\Users (admin); --home reads one user folder (e.g. a
// profile in a mounted image); a file argument reads one copied database.
// Read-only (files are opened with full sharing; a running browser is fine).
// Usage:
//   winspect browser [<History | places.sqlite> | --home <user folder> | --all-users] [--downloads]
//                    [--since <hours>] [--flagged] [--json | --csv]
int cmd_browser(int argc, char **argv);

#endif
