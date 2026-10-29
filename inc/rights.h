#ifndef WINSPECT_RIGHTS_H
#define WINSPECT_RIGHTS_H

// Access-mask decoding by object type: turns 0x000F003F on a Key into
// "QUERY_VALUE|SET_VALUE|CREATE_SUBKEY|ENUM_SUBKEYS|NOTIFY|CREATE_LINK|DELETE|
// READ_CONTROL|WRITE_DAC|WRITE_OWNER". The low 16 bits of a mask mean
// different things per object type (bit 0x10 is VM_READ on a process but
// SET_CONTEXT on a thread), so the type picks the table; the standard and
// generic rights are decoded for every type, and leftover bits print in hex
// so nothing is hidden. The numeric values are from the public Windows SDK
// definitions; written out here so the module needs no Windows headers and is
// unit-tested on any OS. Shared by secinfo and handles.

#include <stddef.h>
#include <stdint.h>

// type: an object type name as NtQueryObject reports it ("File", "Key",
// "Process", "Thread", "Token", "Section", "Event", "Mutant", "Semaphore",
// "Directory"), or "Service". Unknown types get standard/generic rights only.
void rights_decode(const char *type, uint32_t mask, char *out, size_t n);

#endif
