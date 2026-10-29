#ifndef WINSPECT_ROUTES_H
#define WINSPECT_ROUTES_H

// winspect routes - the IPv4 routing table (destination/mask/gateway/metric).
// An unexpected route can silently redirect traffic, so it is worth a look.
// Read-only. Usage: winspect routes [--json | --csv]
int cmd_routes(int argc, char **argv);

#endif
