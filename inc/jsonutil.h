#ifndef WINSPECT_JSONUTIL_H
#define WINSPECT_JSONUTIL_H

// How a command should render its output. Commands parse --json / --csv into
// this and branch on it; the default is human-readable text.
enum out_mode { OUT_TEXT, OUT_JSON, OUT_CSV };

// Minimal JSON output helper shared by commands that support --json.
// json_str prints a single JSON string literal (with surrounding quotes) to
// stdout, escaping the characters JSON requires. It is intentionally tiny: the
// commands assemble the surrounding object/array structure with plain printf and
// use this only for string values, so the whole thing stays easy to audit.
void json_str(const char *s);

// Prints one CSV field for a value that may contain commas, quotes or newlines.
// Per RFC 4180 the field is wrapped in double quotes and inner quotes doubled,
// but only when it actually needs quoting, so plain values stay unquoted.
void csv_str(const char *s);

#endif
