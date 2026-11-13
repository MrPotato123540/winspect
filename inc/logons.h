#ifndef WINSPECT_LOGONS_H
#define WINSPECT_LOGONS_H

// winspect logons - who logged on, how, from where and for how long: the
// Windows counterpart of `last`. Reads the Security log (4624 logon, 4634 /
// 4647 logoff, 4648 explicit credentials, 4672 administrator-equivalent
// session, 4778 / 4779 reconnect / disconnect) and the Terminal Services
// LocalSessionManager log (21 / 23 / 24 / 25), pairs each logon with its
// logoff by logon ID to give a duration, and marks sessions that received
// special privileges as "admin". Service logons and the built-in / machine
// accounts are most of the log and are hidden unless --all is given.
// Flagged, each with a fact that is in the event itself: remote desktop or
// network logon from a public address, remote desktop from loopback (a
// tunnelled connection), cleartext network logon (type 8),
// new-credentials logon by seclogo (type 9: runas /netonly - and what
// pass-the-hash tools produce), NTLMv1, and a success that follows ten or
// more failures (4625) from the same source within the hour (password
// guessing that worked). --failed lists the failed logons themselves, with
// the reason Windows recorded (wrong password, no such user, locked out ...). Passwords are never in these events.
// --summary groups by account, logon type and source (count, first, last).
// --evtx <file> (repeatable) reads copied logs with winspect's own parser.
// --since <hours>, --user <text>, --type <n> and --flagged narrow the list;
// --max <n> bounds the events read per live channel (default 5000).
// The Security log needs elevation. Read-only. Usage:
//   winspect logons [--evtx <file> ...] [--since <hours>] [--user <text>] [--type <n>]
//                   [--all] [--failed] [--flagged] [--summary] [--max <n>] [--json | --csv]
int cmd_logons(int argc, char **argv);

#endif
