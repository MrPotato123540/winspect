#ifndef WINSPECT_AMCACHE_H
#define WINSPECT_AMCACHE_H

// winspect amcache - programs recorded in Amcache.hve: full path, SHA-1,
// publisher / product / version and the time the entry was written, from both
// the older Root\File layout and the Windows 10+ Root\InventoryApplicationFile
// layout. The SHA-1 lets you look a file up in threat intel even after it was
// deleted. Flags files in user-writable dirs. The live file
// (%SystemRoot%\AppCompat\Programs\Amcache.hve) is locked by Windows: copy it
// first (backup / VSS tool) and pass the copy. Read-only. Usage:
//   winspect amcache [<Amcache.hve>] [--sha1 <hash>] [--find <text>] [--flagged] [--json | --csv]
int cmd_amcache(int argc, char **argv);

#endif
