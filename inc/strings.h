#ifndef WINSPECT_STRINGS_H
#define WINSPECT_STRINGS_H

// winspect strings - extract printable ASCII and UTF-16LE strings from a file,
// and flag the ones that look like indicators (URLs, IPs, registry paths, file
// paths). The static-triage counterpart of the Sysinternals `strings` tool.
// Usage: winspect strings <path> [-n <minlen>] [--ioc] [--json | --csv]
int cmd_strings(int argc, char **argv);

#endif
