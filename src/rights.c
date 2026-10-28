// rights - per-object-type access-mask names (see rights.h)

#include "rights.h"

#include <stdio.h>
#include <string.h>

struct rbit { uint32_t bit; const char *name; };

static const struct rbit r_file[] = {
    { 0x0001, "READ_DATA" }, { 0x0002, "WRITE_DATA" }, { 0x0004, "APPEND_DATA" },
    { 0x0008, "READ_EA" }, { 0x0010, "WRITE_EA" }, { 0x0020, "EXECUTE" },
    { 0x0040, "DELETE_CHILD" }, { 0x0080, "READ_ATTR" }, { 0x0100, "WRITE_ATTR" }, { 0, 0 } };
static const struct rbit r_process[] = {
    { 0x0001, "TERMINATE" }, { 0x0002, "CREATE_THREAD" }, { 0x0004, "SET_SESSIONID" },
    { 0x0008, "VM_OPERATION" }, { 0x0010, "VM_READ" }, { 0x0020, "VM_WRITE" },
    { 0x0040, "DUP_HANDLE" }, { 0x0080, "CREATE_PROCESS" }, { 0x0100, "SET_QUOTA" },
    { 0x0200, "SET_INFO" }, { 0x0400, "QUERY_INFO" }, { 0x0800, "SUSPEND_RESUME" },
    { 0x1000, "QUERY_LIMITED" }, { 0x2000, "SET_LIMITED" }, { 0, 0 } };
static const struct rbit r_thread[] = {
    { 0x0001, "TERMINATE" }, { 0x0002, "SUSPEND_RESUME" }, { 0x0008, "GET_CONTEXT" },
    { 0x0010, "SET_CONTEXT" }, { 0x0020, "SET_INFO" }, { 0x0040, "QUERY_INFO" },
    { 0x0080, "SET_THREAD_TOKEN" }, { 0x0100, "IMPERSONATE" },
    { 0x0200, "DIRECT_IMPERSONATION" }, { 0x0400, "SET_LIMITED" },
    { 0x0800, "QUERY_LIMITED" }, { 0x1000, "RESUME" }, { 0, 0 } };
static const struct rbit r_key[] = {
    { 0x0001, "QUERY_VALUE" }, { 0x0002, "SET_VALUE" }, { 0x0004, "CREATE_SUBKEY" },
    { 0x0008, "ENUM_SUBKEYS" }, { 0x0010, "NOTIFY" }, { 0x0020, "CREATE_LINK" },
    { 0x0100, "WOW64_64KEY" }, { 0x0200, "WOW64_32KEY" }, { 0, 0 } };
static const struct rbit r_service[] = {
    { 0x0001, "QUERY_CONFIG" }, { 0x0002, "CHANGE_CONFIG" }, { 0x0004, "QUERY_STATUS" },
    { 0x0008, "ENUM_DEPENDENTS" }, { 0x0010, "START" }, { 0x0020, "STOP" },
    { 0x0040, "PAUSE_CONTINUE" }, { 0x0080, "INTERROGATE" }, { 0x0100, "USER_CONTROL" }, { 0, 0 } };
static const struct rbit r_token[] = {
    { 0x0001, "ASSIGN_PRIMARY" }, { 0x0002, "DUPLICATE" }, { 0x0004, "IMPERSONATE" },
    { 0x0008, "QUERY" }, { 0x0010, "QUERY_SOURCE" }, { 0x0020, "ADJUST_PRIVILEGES" },
    { 0x0040, "ADJUST_GROUPS" }, { 0x0080, "ADJUST_DEFAULT" }, { 0x0100, "ADJUST_SESSIONID" }, { 0, 0 } };
static const struct rbit r_section[] = {
    { 0x0001, "QUERY" }, { 0x0002, "MAP_WRITE" }, { 0x0004, "MAP_READ" },
    { 0x0008, "MAP_EXECUTE" }, { 0x0010, "EXTEND_SIZE" }, { 0x0020, "MAP_EXECUTE_EXPLICIT" }, { 0, 0 } };
static const struct rbit r_event[] = {      // also Semaphore
    { 0x0001, "QUERY_STATE" }, { 0x0002, "MODIFY_STATE" }, { 0, 0 } };
static const struct rbit r_mutant[] = {
    { 0x0001, "QUERY_STATE" }, { 0, 0 } };
static const struct rbit r_directory[] = {
    { 0x0001, "QUERY" }, { 0x0002, "TRAVERSE" }, { 0x0004, "CREATE_OBJECT" },
    { 0x0008, "CREATE_SUBDIRECTORY" }, { 0, 0 } };

static const struct rbit r_keyedevent[] = {
    { 0x0001, "WAIT" }, { 0x0002, "WAKE" }, { 0, 0 } };
static const struct rbit r_job[] = {
    { 0x0001, "ASSIGN_PROCESS" }, { 0x0002, "SET_ATTRIBUTES" }, { 0x0004, "QUERY" },
    { 0x0008, "TERMINATE" }, { 0x0010, "SET_SECURITY_ATTRIBUTES" }, { 0x0020, "IMPERSONATE" }, { 0, 0 } };

static const struct rbit r_standard[] = {
    { 0x00010000, "DELETE" }, { 0x00020000, "READ_CONTROL" }, { 0x00040000, "WRITE_DAC" },
    { 0x00080000, "WRITE_OWNER" }, { 0x00100000, "SYNCHRONIZE" },
    { 0x01000000, "ACCESS_SYS_SECURITY" }, { 0x02000000, "MAXIMUM_ALLOWED" },
    { 0x10000000, "GENERIC_ALL" }, { 0x20000000, "GENERIC_EXECUTE" },
    { 0x40000000, "GENERIC_WRITE" }, { 0x80000000u, "GENERIC_READ" }, { 0, 0 } };

static const struct rbit *table_for(const char *type)
{
    static const struct { const char *type; const struct rbit *tbl; } map[] = {
        { "File", r_file }, { "Process", r_process }, { "Thread", r_thread },
        { "Key", r_key }, { "Service", r_service }, { "Token", r_token },
        { "Section", r_section }, { "Event", r_event }, { "Semaphore", r_event },
        { "Mutant", r_mutant }, { "Directory", r_directory },
        { "KeyedEvent", r_keyedevent }, { "IoCompletion", r_event }, { "Timer", r_event },
        { "Job", r_job },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (strcmp(type, map[i].type) == 0) {
            return map[i].tbl;
        }
    }
    return NULL;
}

void rights_decode(const char *type, uint32_t mask, char *out, size_t n)
{
    if (n == 0) return;
    out[0] = '\0';
    size_t pos = 0;
    int first = 1;
    uint32_t rest = mask;
#define APPEND(s) do { \
        int w_ = snprintf(out + pos, pos < n ? n - pos : 0, "%s%s", first ? "" : "|", (s)); \
        if (w_ > 0) pos += (size_t)w_; \
        if (pos >= n) pos = n - 1; \
        first = 0; } while (0)
    const struct rbit *t = table_for(type ? type : "");
    for (int pass = 0; pass < 2; pass++) {
        const struct rbit *tbl = pass == 0 ? t : r_standard;
        for (; tbl != NULL && tbl->name != NULL; tbl++) {
            if ((mask & tbl->bit) == tbl->bit) {
                APPEND(tbl->name);
                rest &= ~tbl->bit;
            }
        }
    }
    if (rest != 0) {
        char hex[16];
        snprintf(hex, sizeof hex, "0x%lX", (unsigned long)rest);
        APPEND(hex);
    }
    if (first) {
        snprintf(out, n, "(none)");
    }
#undef APPEND
}
