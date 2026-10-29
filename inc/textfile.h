#ifndef WINSPECT_TEXTFILE_H
#define WINSPECT_TEXTFILE_H

// Whole text file (up to 64 MB) as NUL-terminated UTF-8, malloc'd; NULL when
// it cannot be read or is empty. The encoding is detected: a UTF-16 BOM, or
// NUL bytes in most odd positions of the first 512 bytes, means UTF-16LE;
// otherwise UTF-8 when the bytes are valid UTF-8, else Windows-1252. A UTF-8
// BOM is kept (callers skip it).
char *read_text_file(const char *path);

#endif
