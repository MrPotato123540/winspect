#ifndef WINSPECT_CAPTURE_H
#define WINSPECT_CAPTURE_H

// Runs fn(argc, argv) with stdout redirected to a temporary file and returns
// what it printed (malloc'd, NUL-terminated, may be empty; NULL if the
// redirection could not be set up). *rc receives the command's exit code.
// Used by sweep (to nest each check's JSON) and timeline (to read it).
typedef int (*capture_fn)(int argc, char **argv);
char *capture_stdout(capture_fn fn, int argc, char **argv, int *rc);

#endif
