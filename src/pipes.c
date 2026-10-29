// winspect pipes - the named pipes present on the system
//
// Named pipes (\\.\pipe\NAME) are a normal IPC mechanism, but also a favourite
// covert channel for C2 and for lateral movement (PsExec, Cobalt Strike's default
// pipe names, ...). The whole pipe namespace shows up as a directory you can list
// with FindFirstFile, so enumerating it is a cheap, read-only triage view: a
// quick scan of the names often stands out. We only list the directory; we never
// open or connect to a pipe.
//
// Names matching a publicly documented DEFAULT pipe of a well-known C2 or
// remote-execution tool (Cobalt Strike, PsExec, RemCom, PAExec) are flagged
// with the tool's name (ioc_pipe_known, unit-tested). Defaults are easy to
// rename, so no match proves nothing; a match is a lead to follow up.

#include "pipes.h"
#include "jsonutil.h"
#include "ioc.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

int cmd_pipes(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "pipes: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "pipes: cannot list the pipe namespace (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }

    if (mode == 0) {
        puts("named pipes (\\\\.\\pipe\\)\n");
    } else if (mode == 2) {
        puts("name,known_tool");
    } else {
        putchar('[');
    }

    unsigned count = 0, flagged = 0;
    int first = 1;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        count++;
        const char *tool = ioc_pipe_known(fd.cFileName);
        if (tool) { flagged++; }
        if (mode == 0) {
            printf("  %s%s%s%s\n", tool ? "[!] " : "    ", fd.cFileName,
                   tool ? "   <- " : "", tool ? tool : "");
        } else if (mode == 2) {
            csv_str(fd.cFileName);
            putchar(',');
            csv_str(tool ? tool : "");
            putchar('\n');
        } else {
            printf("%s{\"name\":", first ? "" : ",");
            json_str(fd.cFileName);
            fputs(",\"known_tool\":", stdout);
            json_str(tool ? tool : "");
            putchar('}');
            first = 0;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (mode == 0) {
        printf("\n%u pipe(s), %u matching a known tool's default name\n", count, flagged);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
