#ifndef WINSPECT_BOOTS_H
#define WINSPECT_BOOTS_H

// winspect boots - when the machine was on: every boot and shutdown from the
// System log (the idea of `last -x` / `uptime` on Linux), with how long each
// session lasted and whether it ended cleanly; who or what asked for each
// shutdown or restart (process, account, stated reason); reboots without a
// clean shutdown (power loss, reset, crash with its bugcheck code); and
// changes of the system clock of a minute or more: every change BACK and
// every change an application made; Windows' own forward adjustments after a
// wake from sleep are counted and hidden unless --all. Why it matters: activity
// cannot have happened while the machine was off, an unexplained restart or
// crash is a lead, and a clock that was set back makes every other timestamp
// of that period suspect. Clock changes are shown, not flagged: time-zone
// fixes, virtual machines and dual-boot systems produce them legitimately.
// Rows are in the order the events were written, so a clock set back shows
// as times that jump backwards - which is exactly what happened.
// --evtx <file> (repeatable) reads a copied System.evtx. --since <hours>
// narrows, --max <n> bounds the events read live (default 5000).
// Read-only. Usage:
//   winspect boots [--evtx <file> ...] [--since <hours>] [--max <n>] [--all] [--json | --csv]
int cmd_boots(int argc, char **argv);

#endif
