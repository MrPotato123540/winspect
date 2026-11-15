#ifndef WINSPECT_USNCMD_H
#define WINSPECT_USNCMD_H

// winspect usn - the NTFS change journal ($Extend\$UsnJrnl:$J, copied with a
// triage tool): every create, delete, rename, data change... with time, file
// name and reasons, oldest first. With --mft the folder of each entry is
// rebuilt from a copy of the same volume's $MFT. Flags deleted programs /
// scripts and files renamed into a program / script name (pdf -> exe).
// --find filters by name and then follows each matched file by its reference,
// so a later rename or delete under another name is shown too; each row then
// carries its $MFT record and sequence (see mft --record). A file deleted
// while another program still had it open is moved by NTFS into the hidden
// \$Extend\$Deleted folder under a hex name; such rows say so, show where the
// file was, and a deleted program there is judged by its real name. --reason filters
// by reason words (create, delete, rename,
// data, security, close...). --live <drive> reads the running system's
// journal and folder names through the documented FSCTL_QUERY_USN_JOURNAL /
// FSCTL_READ_USN_JOURNAL / FSCTL_ENUM_USN_DATA (administrator). Read-only.
// Usage:
//   winspect usn <$J file> [--mft <$MFT>] | --live <drive> [--find <text>] [--reason <words>] [--flagged] [--json | --csv]
int cmd_usn(int argc, char **argv);

#endif
