#ifndef WINSPECT_BOOTPARSE_H
#define WINSPECT_BOOTPARSE_H

// Boot / shutdown / clock events of the System log as one record type.
// Portable, unit-tested. Event IDs are only meaningful together with their
// provider (12 and 13 mean other things elsewhere), so both are checked.
//   Microsoft-Windows-Kernel-General 12   the OS started (StartTime)
//                                    13   the OS is shutting down (StopTime)
//                                    1    the system time was changed (OldTime, NewTime,
//                                         Reason: 1 = "an application or system component
//                                         changed the time"; other values are Windows'
//                                         own adjustments, e.g. after waking from sleep)
//   Microsoft-Windows-Kernel-Power   41   rebooted without a clean shutdown
//                                         (BugcheckCode: non-zero after a crash)
//   EventLog                         6008 the previous shutdown was unexpected
//                                         (strings: time, date - in LOCAL time and format)
//   User32                           1074 a process asked for a shutdown / restart
//                                         (strings: process, computer, reason,
//                                         reason code, type, comment, user)
// 6008 and 1074 carry their strings by position: unnamed <Data> in older logs,
// <Data Name="param1"> ... on current Windows. Both are read by position.

#include <stddef.h>
#include <stdint.h>

enum boot_kind { BK_NONE = 0, BK_START, BK_STOP, BK_CLOCK, BK_POWER_LOSS, BK_UNEXPECTED, BK_REQUEST };

typedef struct {
    enum boot_kind kind;
    unsigned id;
    char time[24];              // event time, "YYYY-MM-DD HH:MM:SS" UTC
    char detail[600];           // one line, built from the event's own fields
    int64_t clock_delta;        // BK_CLOCK: new - old, seconds
    int clock_reason;           // BK_CLOCK: the event's Reason, -1 when absent (older Windows)
    char user[200];             // BK_REQUEST
    char process[300];          // BK_REQUEST
    char action[40];            // BK_REQUEST: "restart", "power off" ...
} boot_rec;

// Returns 1 and fills r when xml is one of the events above, else 0.
int boot_parse(const char *xml, boot_rec *r);

// Text of the n-th (0-based) <Data> element WITHOUT a Name attribute.
// Returns 1 if it exists.
int evt_data_nth(const char *xml, int n, char *out, size_t cap);

// Text of the n-th (0-based) <Data> element, named or not. Returns 1 if it exists.
int evt_data_pos(const char *xml, int n, char *out, size_t cap);

// Name attribute of <Provider ...>. Returns 1 if found.
int evt_provider(const char *xml, char *out, size_t cap);

// "YYYY-MM-DD?HH:MM:SS..." (any separator) -> seconds since 1970, -1 if malformed.
int64_t iso_epoch(const char *s);

// "3d 4h", "2h 13m", "45s" for a number of seconds (absolute value is used).
void fmt_span(int64_t seconds, char *out, size_t n);

const char *boot_kind_name(enum boot_kind k);

#endif
