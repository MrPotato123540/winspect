// Run a command function with its stdout captured (see capture.h).
//
// The command prints with printf/puts as usual; stdout's file descriptor is
// pointed at a temporary file for the duration of the call and restored
// afterwards, then the file's contents are returned. stderr is untouched, so
// a command's error messages still reach the user.

#include "capture.h"

#include <io.h>
#include <stdio.h>
#include <stdlib.h>

// Runs fn with stdout redirected to a temp file; returns the captured text
// (malloc'd, may be empty) and the command's exit code via *rc.
char *capture_stdout(capture_fn fn, int argc, char **argv, int *rc)
{
    *rc = 1;
    FILE *tmp = tmpfile();
    if (tmp == NULL) return NULL;
    fflush(stdout);
    int saved = _dup(_fileno(stdout));
    // _dup2 returns 0 on success, not a new descriptor (GCC's -fanalyzer models
    // it as dup2 and reports a bogus fd leak here, hence the pragma).
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 13
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif
    if (saved < 0 || _dup2(_fileno(tmp), _fileno(stdout)) != 0) {
        if (saved >= 0) _close(saved);
        fclose(tmp);
        return NULL;
    }
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 13
#pragma GCC diagnostic pop
#endif
    *rc = fn(argc, argv);
    fflush(stdout);
    _dup2(saved, _fileno(stdout));
    _close(saved);

    long len = 0;
    char *text = NULL;
    if (fseek(tmp, 0, SEEK_END) == 0 && (len = ftell(tmp)) >= 0 &&
            fseek(tmp, 0, SEEK_SET) == 0) {
        text = (char *)malloc((size_t)len + 1);
        if (text != NULL) {
            size_t got = fread(text, 1, (size_t)len, tmp);
            text[got] = '\0';
        }
    }
    fclose(tmp);
    return text;
}
