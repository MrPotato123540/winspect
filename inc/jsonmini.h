#ifndef WINSPECT_JSONMINI_H
#define WINSPECT_JSONMINI_H

// jsonmini - a small, strict JSON reader for winspect's OWN output (timeline
// reads what other commands print with --json). RFC 8259 values: objects,
// arrays, strings (all escapes, \uXXXX incl. surrogate pairs -> UTF-8),
// numbers, true/false/null. Nesting is limited to 64 levels; anything
// malformed returns NULL. Portable C, no Windows API.

#include <stddef.h>

typedef enum { JM_NULL, JM_BOOL, JM_NUM, JM_STR, JM_ARR, JM_OBJ } jm_type;

typedef struct jm_node {
    jm_type type;
    char *key;                  // member name when the parent is an object
    char *str;                  // JM_STR
    double num;                 // JM_NUM
    int boolean;                // JM_BOOL
    struct jm_node *child;      // first element / member (JM_ARR, JM_OBJ)
    struct jm_node *next;       // next sibling
} jm_node;

jm_node *jm_parse(const char *text, size_t len);
void jm_free(jm_node *n);
// Member of an object by name (NULL if absent or not an object).
const jm_node *jm_get(const jm_node *obj, const char *key);
// String member, or NULL when absent / not a string.
const char *jm_gets(const jm_node *obj, const char *key);

#endif
