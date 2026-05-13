#include "cmdln.h"

void prtUsage(int argc, const char* argv[], const char *msg="") {
 if (msg && *msg)
    fprintf(stderr, "Error: %s.\n", msg);
 fprintf(stderr, "Usage: %s ", argv[0]);
 fprintf(stderr, 
  " [-#] [-c] [-d|-s] [-f flushInterval] {-i myIP}+\n"
  "[-l logLevel] [-L] {-n neAddr/netMask}+ [-o] [-pf] [-ps] [-u] [-V] [-w width]\n"
  "[-[I|C] <auditFile>] [-P <printFile1>] [-S <printFile2>] [-R <recordFile>]\n"
  "  -#: indicates that processor core #s are included in capture file\n"
  "  -c: sort file and socket usage counts by frequency.\n"
  "  -C <file>: store eaudit records to the specified file.\n"
  "     <file> can be of the form [<protocol>:[//<host]/]]<filename> where:\n"
  "       -- <protocol> is one of ssh, gzip, gzipfast, ssh+gzip, ssh+gzipfast,\n"
  "          gzip+ssh, or gzipfast+ssh.\n"
  "       -- <host> is of the form [user@]remhost, and\n"
  "       -- <filename> is a simple file name.\n"
  "  -d: when running with full Host, produce a dump file from Host.\n"
  "  -s: when running with full Host, print a summary from Host.\n"
  "  -f <num>: flush idle caches every <num> seconds, e.g., 0.001.\n"
  "  -i: specify this host's IP addresses. Can be used multiple times.\n"
  "  -I: specify the input file (eaudit capture file).\n"
  "  -l logLevel: specify logging level, defaults to %d.\n", ERRLEVEL);
 fprintf(stderr,
  "  -L: input contains 32-bit sequence numbers instead of the default 16-bit.\n"
  "  -n: specify this host's network addresses and network masks.\n"
  "  -o: toggle defaults to look up missing process/file info using /proc etc.\n"
  "  -pf: print the list of files accessed.\n"
  "  -ps: print the list of sockets accessed.\n"
  "  -P: print syscalls in readable format immediately on parsing.\n"
  "  -R <file>: create record file for Host. For format of <file>, see -C above.\n"
  "  -S: print syscalls after arranging them in correct serial order.\n"
  "  -t <n>: Set a tamper window n times the flush interval.\n"
  "  -u: use microsecond granularity timestamp when printing.\n"
  "  -V: enable MAC verification of log records.\n"
  "  -w width: format output for display with width columns.\n"
  "This program can operate online or offline. In online mode, captured syscall\n"
  "records are processed by this program and saved to a capture file and/or a\n"
  "record file. In offline mode, an eaudit capture file is read and printed, or\n"
  "converted to record file format. Not all options are meaningful in both modes."
  "\nFile names can be specified as \"-\" to denote stdin/stdout. If -I option\n"
  "is missing in offline mode, eaudit records are read from stdin. Record file\n"
  "will use gzip compression if <recordFile> ends with .gz. During recording,\n"
  "missing process and file information can be looked up by reading files in\n"
  "/proc and by making stat calls. This is the default in online mode, but not\n"
  "in offline mode. Use -o to toggle this default.\n");
  exit(1);
}

bool online_mode=false;
bool use_procid = false, sortByFreq=true, host_dump=false, host_summary=false;
const char* capturefn=nullptr, *recfn=nullptr, *prtpfn=nullptr, *prtcfn=nullptr;
// Optional user override for flushInterval, parsed from -f in seconds. A value
// <= 0 means no override was supplied, so eauditd.C keeps its derived default.
float user_flushInterval;
vector<unsigned> *ipaddrs=nullptr, *netmasks=nullptr, *netaddrs=nullptr;
int logLevel=ERRLEVEL; // WARNLEVEL, ERRLEVEL, etc. Zero means don't complain
bool long_seqnum=false, lookupProc, summarizeFiles=false, summarizeEP=false;
bool prtInParser=false, prtInConsumer=false, prt_musec_ts=false;
bool verifyLog=false;
long tamperWindow;
int width=80;

void
parseCmdLine(int argc, const char* argv[]) {
   lookupProc = online_mode;

   for (int i=1; i < argc; i++) {
      if (argv[i][0] == '-') {
         switch (argv[i][1]) {
         case '#':
            use_procid = !use_procid;
            break;

         case 'c': sortByFreq=true; break;

         case 'C':
         case 'I':
            if (++i >= argc)
               prtUsage(argc, argv, "-I and -C options require a filename");
            capturefn = argv[i];
            break;

         case 'd':
#ifdef FULL_HOST
            host_dump = true;
            if (!recfn)
               recfn = "/dev/null";
#else
            fprintf(stderr, "-d option not supported on this binary\n");
#endif
            break;

         case 's':
#ifdef FULL_HOST
            host_summary = true;
            if (!recfn)
               recfn = "/dev/null";
#else
            fprintf(stderr, "-s option not supported on this binary\n");
#endif
            break;

         case 'f':
            if (++i >= argc)
               prtUsage(argc, argv, "-f option require a numeric argument");
            sscanf(argv[i], "%g", &user_flushInterval);
            break;

         case 'i': {
            unsigned r1, r2, r3, r4;
            if (++i >= argc ||
                 (sscanf(argv[i], "%d.%d.%d.%d", &r1, &r2, &r3, &r4) < 4))
                prtUsage(argc, argv, 
                  "-i option require an IP address argument in octet format");
            if (!ipaddrs) ipaddrs = new vector<unsigned>;
            ipaddrs->push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            break;
         }

         case 'l':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &logLevel) < 1))
               prtUsage(argc, argv, "-l option requires a loglevel argument");
            break;

         case 'L':
            long_seqnum = true;
            break;

         case 'n': {
            unsigned r1, r2, r3, r4, r5, r6, r7, r8;
            if (++i >= argc ||
                (sscanf(argv[i], "%d.%d.%d.%d/%d.%d.%d.%d", &r1, &r2, 
                  &r3, &r4, &r5, &r6, &r7, &r8) < 8))
               prtUsage(argc, argv, "-n option requires an argument in "
                        "netaddr/netmask format, both octets");
            if (!netaddrs) netaddrs = new vector<unsigned>;
            if (!netmasks) netmasks = new vector<unsigned>;
            netaddrs->push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            netmasks->push_back((r5<<24)+(r6<<16)+(r7<<8)+r8);
            break;
         }

         case 'o': lookupProc = !lookupProc; break;

         case 'p':
            if (argv[i][2] == 'f')
               summarizeFiles = true;
            else if (argv[i][2] == 's')
               summarizeEP = true;
            else prtUsage(argc, argv);
            break;


         case 'P':
            // if (!prtInConsumer)
               prtInParser = true;
            if (++i >= argc || !*(argv[i]))
               prtUsage(argc, argv, "-P option requires a filename");
            prtpfn = argv[i];
            break;

         case 'R':
            if (++i >= argc || !*(argv[i]))
               prtUsage(argc, argv, "-R option requires a filename");
            recfn = argv[i];
            break;

         case 'S':
            // prtInParser = false;
            prtInConsumer = true;
            // if (!recfn)
            //   recfn = "/dev/null";
            if (++i >= argc || !*(argv[i]))
               prtUsage(argc, argv, "-S option requires a filename");
            prtcfn = argv[i];
            break;

         case 't':
            if (++i >= argc ||
                (sscanf(argv[i], "%ld", &tamperWindow) < 1))
               prtUsage(argc, argv, "-t option requires an integer argument");
            if (10 > tamperWindow || tamperWindow > 1000)
               prtUsage(argc, argv, "-t: valid argument range is 10 to 1000");
            break;

         case 'u':
            prt_musec_ts = true;
            break;

         case 'V':
            verifyLog = true;
            break;

         case 'w':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &width) < 1)) {
               i--;
               width = 132;
            }
            break;

         default: prtUsage(argc, argv, "Unrecognized option"); break;
         }
      }
   }
}
