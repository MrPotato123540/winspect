#ifndef WINSPECT_WER_H
#define WINSPECT_WER_H

// winspect wer - Windows Error Reporting crash / hang reports (Report.wer)
// as execution evidence: a program that crashed certainly ran, and its
// report keeps the full path, the time, the faulting module and the
// exception code long after the file itself is gone. Malware and exploits
// crash more often than they should (and a crash inside a browser or Office
// with an odd fault module is where an exploit attempt shows). Read from
// ProgramData\Microsoft\Windows\WER (ReportArchive, ReportQueue) and each
// profile's AppData\Local\Microsoft\Windows\WER. Columns: time (UTC), event
// type, program, fault module, exception code, path; --modules adds the
// first module loaded from a user-writable folder (shown, not flagged:
// overlays and per-user add-ins do this legitimately). Flagged: the crashed
// program itself ran from a user-writable folder. A folder argument reads
// reports below it instead (a copy from an image). Read-only. Usage:
//   winspect wer [<folder>] [--find <text>] [--modules] [--flagged] [--json | --csv]
int cmd_wer(int argc, char **argv);

#endif
