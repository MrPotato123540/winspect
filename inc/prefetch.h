#ifndef WINSPECT_PREFETCH_H
#define WINSPECT_PREFETCH_H

// winspect prefetch - evidence of execution from %SystemRoot%\Prefetch\*.pf:
// executable name, run count, last run time(s) and - from the file's own
// list of referenced files - the full path it ran from; runs from
// user-writable dirs (Temp, Downloads, AppData) are flagged. Windows 10+
// stores these files MAM/XPRESS-Huffman compressed; we decompress them with
// ntdll's own RtlDecompressBufferEx. Reading the folder usually needs
// elevation. Read-only. Usage:
//   winspect prefetch [<file.pf> [--files] | --dir <path>] [--flagged] [--json | --csv]
// --files lists the volumes and files the program touched while starting;
// --flagged keeps only flagged programs.
int cmd_prefetch(int argc, char **argv);

#endif
