#ifndef WINSPECT_NET_H
#define WINSPECT_NET_H

// winspect net - per-process TCP/UDP endpoints (who owns which connection).
// --external keeps connections to public addresses; --exposed keeps sockets
// listening on every interface (0.0.0.0 / ::). Flags (with a reason) script
// hosts or programs in user-writable dirs that talk to public addresses or
// listen on all interfaces; --flagged shows only those.
// Usage: winspect net [pid | name] [--tcp] [--udp] [--listening] [--established]
//                     [--external] [--exposed] [--flagged]
//                     [--json | --csv]
// With a pid, only that process's endpoints are shown; without one, all. Each
// row names the owning process. --tcp/--udp pick a family; --listening shows
// listening/bound sockets, --established only live TCP connections.
int cmd_net(int argc, char **argv);

#endif
