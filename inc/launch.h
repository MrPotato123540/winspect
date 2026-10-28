#ifndef WINSPECT_LAUNCH_H
#define WINSPECT_LAUNCH_H

// winspect launch - start a program SUSPENDED, show where it is about to begin
// (image base after ASLR, entry point, the first bytes there), then resume it
// normally - the loader's-eye view of process birth, as a debugger sees it.
// It starts the program you name, so use it only on programs you trust.
// Usage:
//   winspect launch <path>
int cmd_launch(int argc, char **argv);

#endif
