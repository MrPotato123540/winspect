#ifndef WINSPECT_PE_H
#define WINSPECT_PE_H

// winspect pe - parse a PE file straight from disk (no process involved): DOS/NT
// headers, optional header, sections with permissions and entropy, imports,
// exports, debug (PDB), TLS callbacks, overlay, security mitigations, imphash,
// exphash, Rich header, version info, .NET header, manifest execution level,
// import capabilities (what the code can call - not a verdict) and an anomaly
// list (checksum mismatch, W+X sections, packer section names, ...).
// Read-only. Usage:
//   winspect pe <path> [--json]
int cmd_pe(int argc, char **argv);

#endif
