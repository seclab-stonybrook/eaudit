#ifndef CMDLN_H
#define CMDLN_H
#include "Base.h"

extern bool online_mode, use_procid, sortByFreq, host_dump, host_summary;
extern const char* capturefn;
extern const char *recfn;
extern const char *prtpfn, *prtcfn;
extern float flushInterval;
extern vector<unsigned> *ipaddrs, *netmasks, *netaddrs;
extern int logLevel;
extern bool long_seqnum, lookupProc, summarizeFiles, summarizeEP;
extern bool prtInParser, prtInConsumer, prt_musec_ts;
extern long tamperWindow;
extern int width;

void parseCmdLine(int argc, const char* argv[]);
#endif
