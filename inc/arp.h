#ifndef WINSPECT_ARP_H
#define WINSPECT_ARP_H

// winspect arp - the IPv4 neighbour (ARP) cache: which IP maps to which MAC on
// the local segment. Read-only. Usage: winspect arp [--json | --csv]
int cmd_arp(int argc, char **argv);

#endif
