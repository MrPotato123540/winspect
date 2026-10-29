// Shannon entropy over a byte buffer - pure math, OS-independent, unit-tested.
// Extracted from the pe command so the calculation can be reused and verified
// against known values (all-same => 0, 50/50 => 1, uniform 256 => 8).

#include "entropy.h"

#include <math.h>

double shannon_entropy(const unsigned char *data, size_t len)
{
    if (len == 0) {
        return 0.0;
    }
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double e = 0.0;
    for (int b = 0; b < 256; b++) {
        if (counts[b] != 0) {
            double p = (double)counts[b] / (double)len;
            e -= p * log2(p);
        }
    }
    return e;
}
