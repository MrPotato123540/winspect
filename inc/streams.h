#ifndef WINSPECT_STREAMS_H
#define WINSPECT_STREAMS_H

// winspect streams - NTFS alternate data streams (ADS) of a file or of every
// file in a folder (--recurse for subfolders). Decodes the Zone.Identifier
// stream (Mark-of-the-Web): the security zone and the URL a file was
// downloaded from. Flags executable content that came from the internet and
// unusual streams that could hide data. Read-only. Usage:
//   winspect streams <file | folder> [--recurse] [--json | --csv]
int cmd_streams(int argc, char **argv);

#endif
