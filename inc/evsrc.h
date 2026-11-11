#ifndef WINSPECT_EVSRC_H
#define WINSPECT_EVSRC_H

// Event sources for commands that consume events as XML text: a live channel
// (EvtQuery, newest first) or a copied .evtx file (winspect's own reader,
// file order). Either way the callback gets the same XML EvtRender produces,
// so one handler serves both. Read-only.

#include <windows.h>

typedef void (*evsrc_cb)(const char *xml, void *ctx);

// Queries `channel` with an XPath filter, newest first, at most `max` events.
// Returns 0, or the Win32 error (ERROR_ACCESS_DENIED: not elevated,
// ERROR_EVT_CHANNEL_NOT_FOUND: no such log on this machine).
DWORD evsrc_live(const char *channel, const char *xpath, unsigned max, evsrc_cb cb, void *ctx);

// Renders every record of an .evtx file. Returns 0, 1 when the file cannot
// be opened and 2 when it is not an EVTX file; *dirty (may be NULL) is set
// when the log was not closed cleanly (copied while in use).
int evsrc_file(const char *path, evsrc_cb cb, void *ctx, int *dirty);

#endif
