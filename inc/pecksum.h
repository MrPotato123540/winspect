#ifndef WINSPECT_PECKSUM_H
#define WINSPECT_PECKSUM_H

#include <stddef.h>
#include <stdint.h>

// The PE image checksum (the value CheckSumMappedFile computes and the optional
// header stores): a folded 16-bit ones-complement-style word sum over the whole
// file, with the 4 bytes of the CheckSum field at `csfield` treated as zero,
// plus the file size. `pe` uses it to flag a file edited after linking. Pure
// arithmetic, OS-independent, unit-tested (tests/test_util.c).
uint32_t pe_checksum(const unsigned char *data, size_t size, size_t csfield);

#endif
