#ifndef WINSPECT_HASH_H
#define WINSPECT_HASH_H

// winspect hash - a file's MD5, SHA1 and SHA256 digests, the identifiers used
// to look a sample up in threat intel. The file is streamed, so its size does
// not matter. Given a folder, every file in it is hashed (-r descends; the
// idea of md5deep / hashdeep). --match <list> looks every hash up in a text
// file of known hashes - an IOC list, or the md5sum / sha256sum output of
// another machine (one hash per line, optionally followed by a label; MD5,
// SHA-1 and SHA-256 may be mixed) - and reports only the files that are on
// it, with the list's label. Read-only. Usage:
//   winspect hash <file | folder> [-r] [--match <hash list>] [--json | --csv]
int cmd_hash(int argc, char **argv);

#endif
