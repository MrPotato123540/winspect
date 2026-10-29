#ifndef WINSPECT_DEFENDER_H
#define WINSPECT_DEFENDER_H

// winspect defender - read-only view of Microsoft Defender exclusions (paths,
// extensions, processes, IPs) from both the local settings and the Group Policy
// keys, plus the policy AND local values that switch protection off (offline:
// --software). An exclusion added by
// an intruder is a classic way to make a folder invisible to the scanner, so
// these lists are worth reviewing. Reading the local lists needs elevation on
// current Windows; an access-denied key is reported, never treated as empty.
// Usage: winspect defender [--software <SOFTWARE>] [--json | --csv]
int cmd_defender(int argc, char **argv);

#endif
