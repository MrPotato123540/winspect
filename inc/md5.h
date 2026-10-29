#ifndef WINSPECT_MD5_H
#define WINSPECT_MD5_H

#include <stddef.h>

// Minimal, self-contained MD5 (RFC 1321). winspect uses it only for fingerprints
// that are defined in terms of MD5 by external tooling - imphash (pefile/YARA)
// and the Rich-header hash. MD5 is cryptographically broken and must NOT be used
// for anything security-sensitive; here it is only an identifier, chosen because
// the whole ecosystem keys on these exact MD5 values.
//
// md5_hex writes a 32-char lowercase hex digest plus a NUL into out (>=33 bytes).
void md5_hex(const unsigned char *data, size_t len, char out[33]);

#endif
