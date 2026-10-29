// PE image checksum - pure arithmetic, OS-independent, unit-tested.
// Extracted from the pe command so the algorithm can be verified in isolation.

#include "pecksum.h"

uint32_t pe_checksum(const unsigned char *data, size_t size, size_t csfield)
{
    unsigned long long sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2) {
        if (i == csfield || i == csfield + 2) {
            continue;   // the CheckSum field itself counts as zero
        }
        unsigned w = (unsigned)data[i] | ((unsigned)data[i + 1] << 8);
        sum += w;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (size & 1) {
        sum += data[size - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint32_t)(sum + size);
}
