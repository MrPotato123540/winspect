#ifndef WINSPECT_JUMPLIST_H
#define WINSPECT_JUMPLIST_H

// winspect jumplist - the current user's Jump Lists: per application (AppID),
// the files and folders recently opened with it, from
// Recent\AutomaticDestinations (compound files holding one shortcut per item)
// and Recent\CustomDestinations (shortcuts stored back to back). Each item
// shows its target, arguments and the target's timestamps. Flags items that
// launch a script host or point into a user-writable dir. Read-only. Usage:
//   winspect jumplist [<file | folder>] [--json | --csv]
int cmd_jumplist(int argc, char **argv);

#endif
