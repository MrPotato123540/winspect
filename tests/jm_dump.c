// jm_dump - read JSON from stdin with jsonmini and print it back in canonical
// form ("INVALID" if rejected). tests/jm_diff.py compares the result with
// Python's json module on random documents.
#include "jsonmini.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static void str(const char *s)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void dump(const jm_node *n)
{
    switch (n->type) {
    case JM_NULL: fputs("null", stdout); break;
    case JM_BOOL: fputs(n->boolean ? "true" : "false", stdout); break;
    case JM_NUM:                    // overflowing exponents become +-inf, as in Python
        if (isinf(n->num)) fputs(n->num < 0 ? "-1e999" : "1e999", stdout);
        else printf("%.17g", n->num);
        break;
    case JM_STR:  str(n->str); break;
    case JM_ARR:
    case JM_OBJ:
        putchar(n->type == JM_ARR ? '[' : '{');
        for (const jm_node *c = n->child; c; c = c->next) {
            if (c != n->child) putchar(',');
            if (n->type == JM_OBJ) { str(c->key); putchar(':'); }
            dump(c);
        }
        putchar(n->type == JM_ARR ? ']' : '}');
        break;
    }
}

int main(void)
{
    static char buf[1 << 22];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    jm_node *r = jm_parse(buf, n);
    if (r == NULL) { puts("INVALID"); return 0; }
    dump(r);
    putchar('\n');
    jm_free(r);
    return 0;
}
