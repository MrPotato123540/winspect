#ifndef WINSPECT_ENTROPY_H
#define WINSPECT_ENTROPY_H

#include <stddef.h>

// Shannon entropy of a byte buffer in bits/byte (0.0 .. 8.0): -sum(p*log2 p)
// over the 256 byte-value frequencies. Used by `pe` to flag packed/encrypted
// sections (a value near 8 is the tell). Pure math, OS-independent, so it is
// unit-tested on any platform (see tests/test_util.c). Returns 0.0 for len == 0.
double shannon_entropy(const unsigned char *data, size_t len);

#endif
