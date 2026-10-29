#ifndef WINSPECT_EVENTS_H
#define WINSPECT_EVENTS_H

// winspect events - a short, high-signal timeline from the Windows event logs:
// services installed (7045/4697), logs cleared (104/1102), failed logons
// (4625), accounts created (4720) and added to groups (4728/4732/4756),
// scheduled tasks created (4698/106), Defender detections and protection
// turned off (1116/1117/5001), RDP logons (1149) and PowerShell script blocks
// Windows itself flagged as suspicious (4104, warning level). Newest first.
// The Security log needs elevation; a denied channel is reported, not hidden.
// --since <hours> keeps only the last <hours> hours. --summary instead groups
// failed logons by source address (failures, distinct accounts, first/last)
// and flags password guessing / spraying patterns.
// Read-only (EvtQuery). Usage:
//   winspect events [--max <n per channel>] [--since <hours>] [--summary] [--json | --csv]
int cmd_events(int argc, char **argv);

#endif
