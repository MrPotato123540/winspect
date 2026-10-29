#ifndef WINSPECT_WEBCACHE_H
#define WINSPECT_WEBCACHE_H

// winspect webcache - Internet Explorer / legacy Edge WebCache
// (WebCacheV01.dat, an ESE database read with winspect's own reader): the
// History containers (pages visited, and local files opened as
// "file:///..." - Windows records those even without a browser in use) and
// the iedownload containers, with the user, access count and times; --all
// adds the Content (cache) containers. Flags visits to and downloads from
// bare IP addresses and downloaded programs. The live file
// (%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat) is locked:
// pass a copy, or --home <user folder> of a mounted image. Read-only. Usage:
//   winspect webcache <WebCacheV01.dat> | --home <user folder> [--all] [--flagged] [--json | --csv]
int cmd_webcache(int argc, char **argv);

#endif
