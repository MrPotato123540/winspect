#ifndef WINSPECT_HASHLIST_H
#define WINSPECT_HASHLIST_H

// A list of known hashes to look files up in (an IOC list, a "known bad"
// set, or the output of md5sum / sha256sum from another machine). Portable,
// unit-tested. Accepted per line, in any mix:
//   <hash>
//   <hash>  <label>          (md5sum style, also "<hash> *file")
//   <hash>,<label>           (CSV; the label ends at the next comma)
// <hash> is 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex digits, any case.
// Blank lines, lines starting with '#' and lines that do not start with such
// a hash are skipped (so a CSV header is harmless).

#include <stddef.h>

typedef struct {
    char hex[65];               // lowercase
    char label[120];
} hl_entry;

typedef struct {
    hl_entry *v;                // sorted by hex
    size_t n;
} hashlist;

// Parses text (modified in place). Returns the number of hashes kept, or -1
// when memory runs out. Free with hashlist_free.
long hashlist_parse(char *text, hashlist *l);
void hashlist_free(hashlist *l);

// The entry for a hash (hex, any case), or NULL.
const hl_entry *hashlist_find(const hashlist *l, const char *hex);

#endif
