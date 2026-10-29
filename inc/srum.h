#ifndef WINSPECT_SRUM_H
#define WINSPECT_SRUM_H

// winspect srum - System Resource Usage Monitor (SRUDB.dat, an ESE database
// read with winspect's own reader): per application and user, hour by hour,
// the bytes sent and received on each network interface (--network, the
// default), CPU / disk use (--apps) and network connection spans
// (--connectivity). --summary adds the network bytes up per application,
// largest upload first - the quickest way to spot data leaving. Flags
// programs in user-writable folders that sent data. The live file
// (%SystemRoot%\System32\sru\SRUDB.dat) is locked: pass a copy (e.g.
// esentutl /y ... /vss). Read-only. Usage:
//   winspect srum <SRUDB.dat> [--network | --apps | --connectivity | --summary]
//                 [--find <app text>] [--flagged] [--json | --csv]
int cmd_srum(int argc, char **argv);

#endif
