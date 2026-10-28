#ifndef WINSPECT_HOSTS_H
#define WINSPECT_HOSTS_H

// winspect hosts - show the active entries in the system hosts file. Malware and
// adware often add lines here to redirect or block domains, so the non-comment
// entries are a quick thing to eyeball. Read-only. Usage:
//   winspect hosts [--json | --csv]
int cmd_hosts(int argc, char **argv);

#endif
