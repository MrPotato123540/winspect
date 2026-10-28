// winspect sessions - the terminal/logon sessions on this machine
//
// Every interactive logon, RDP connection and the services session shows up as a
// Terminal Services session. WTSEnumerateSessions lists them and
// WTSQuerySessionInformation fills in the signed-in user; together they answer
// "who is logged on, and how?" - a baseline/triage question (an unexpected active
// session or user is worth noticing). Read-only enumeration only.

#include "sessions.h"
#include "jsonutil.h"

#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *state_name(WTS_CONNECTSTATE_CLASS s)
{
    switch (s) {
    case WTSActive:       return "active";
    case WTSConnected:    return "connected";
    case WTSConnectQuery: return "connect-query";
    case WTSShadow:       return "shadow";
    case WTSDisconnected: return "disconnected";
    case WTSIdle:         return "idle";
    case WTSListen:       return "listen";
    case WTSReset:        return "reset";
    case WTSDown:         return "down";
    case WTSInit:         return "init";
    default:              return "?";
    }
}

// Queries one string info class for a session, copying it into out. The WTS API
// hands back a buffer we must release with WTSFreeMemory.
static void query_str(DWORD sid, WTS_INFO_CLASS cls, char *out, size_t n)
{
    out[0] = '\0';
    LPSTR buf = NULL;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sid, cls, &buf, &bytes) &&
        buf != NULL) {
        snprintf(out, n, "%s", buf);
        WTSFreeMemory(buf);
    }
}

int cmd_sessions(int argc, char **argv)
{
    int mode = 0;   // 0 text, 1 json, 2 csv
    for (int a = 0; a < argc; a++) {
        if (strcmp(argv[a], "--json") == 0)      mode = 1;
        else if (strcmp(argv[a], "--csv") == 0)  mode = 2;
        else {
            fprintf(stderr, "sessions: unexpected argument '%s'\n", argv[a]);
            return 1;
        }
    }

    WTS_SESSION_INFOA *info = NULL;
    DWORD count = 0;
    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count)) {
        fprintf(stderr, "sessions: WTSEnumerateSessions failed (error %lu)\n",
                (unsigned long)GetLastError());
        return 1;
    }

    if (mode == 0) {
        printf("  %-4s %-16s %-14s %s\n", "id", "winstation", "state", "user");
    } else if (mode == 2) {
        puts("id,winstation,state,user");
    } else {
        putchar('[');
    }

    int first = 1;
    for (DWORD i = 0; i < count; i++) {
        DWORD sid = info[i].SessionId;
        const char *ws = info[i].pWinStationName ? info[i].pWinStationName : "";
        const char *state = state_name(info[i].State);
        char user[256], domain[256], full[520];
        query_str(sid, WTSUserName, user, sizeof user);
        query_str(sid, WTSDomainName, domain, sizeof domain);
        if (user[0] && domain[0]) {
            snprintf(full, sizeof full, "%s\\%s", domain, user);
        } else {
            snprintf(full, sizeof full, "%s", user);
        }

        if (mode == 0) {
            printf("  %-4lu %-16s %-14s %s\n", (unsigned long)sid, ws, state,
                   full[0] ? full : "-");
        } else if (mode == 2) {
            printf("%lu,", (unsigned long)sid);
            csv_str(ws);    putchar(',');
            csv_str(state); putchar(',');
            csv_str(full);  putchar('\n');
        } else {
            printf("%s{\"id\":%lu,\"winstation\":", first ? "" : ",", (unsigned long)sid);
            json_str(ws);
            fputs(",\"state\":", stdout); json_str(state);
            fputs(",\"user\":", stdout);  json_str(full);
            putchar('}');
            first = 0;
        }
    }
    WTSFreeMemory(info);

    if (mode == 0) {
        printf("\n%lu session(s)\n", (unsigned long)count);
    } else if (mode == 1) {
        puts("]");
    }
    return 0;
}
