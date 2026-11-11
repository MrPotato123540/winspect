#ifndef WINSPECT_WERPARSE_H
#define WINSPECT_WERPARSE_H

// Windows Error Reporting report files (Report.wer): a "Key=Value" text file
// written when a program crashes or hangs. Portable, unit-tested.
//   EventType=APPCRASH            what happened (APPCRASH, BEX64, AppHangB1, MoAppCrash, ...)
//   EventTime=132537642905441711  FILETIME (UTC) as a decimal number
//   AppPath=C:\dir\app.exe        full path of the program (newer reports)
//   AppName=...  / NsAppName=app.exe / OriginalFilename=
//   Sig[n].Name=Fault Module Name      the problem signature is a list of
//   Sig[n].Value=some.dll              name / value pairs; which names exist
//                                      depends on the event type
//   LoadedModule[n]=C:\...\x.dll  modules in the process when it died
// Older reports carry the program path only as LoadedModule[0] or UI[2].

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char event_type[64];
    uint64_t event_time;        // FILETIME, 0 = absent
    char app_name[160];         // Sig "Application Name" / NsAppName / AppName
    char app_path[520];
    char fault_module[160];     // Sig "Fault Module Name"
    char exc_code[32];          // Sig "Exception Code" (not "exception_code": a macro in excpt.h)
    char report_id[64];
    unsigned modules;           // LoadedModule[] lines
    unsigned modules_writable;  // of those, in user-writable folders
    char first_writable_module[520];
} wer_report;

// Parses the text of a Report.wer (UTF-8, modified in place: lines are cut).
// Returns 0, or -1 when the text has none of the keys above (not a report).
int wer_parse(char *text, wer_report *r);

// Why a report deserves a look, or NULL: the crashed program ran from a
// user-writable folder.
const char *wer_reason(const wer_report *r);

#endif
