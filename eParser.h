#include <vector>

#include <sys/socket.h>
#include <asm/types.h>
#include <sys/un.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <vector>
#include "STLutils.h"

union saddr_t {
   struct sockaddr_un sun;
   struct sockaddr_in sin;
   struct sockaddr_in6 sin6;
   struct sockaddr_nl snl;
};

using namespace std;

string countReadable(long c);
string countReadable(long count, int w);
void prtSortedCounts(long count[], const char* const name[], unsigned sz, 
         const char* title="", const char* hdg="", int width=80, FILE* fp=stderr);
void prtSum(int width=80);

void parser_init(const char* infn=nullptr, const char* prtfn=nullptr, 
        const char* recfn=nullptr, bool use_seqnum=true, bool use_procid=false, 
        bool auditRdWr=true, bool logOpen=false, bool summarizeFiles=false, 
        bool summarizeEP=false, bool sortByFreq=true,
        const vector<unsigned>* ipaddrs=nullptr, 
        const vector<unsigned>* netmasks=nullptr, 
        const vector<unsigned>* netaddrs=nullptr);

void parse_stream();
void parse_rec(const char *p, size_t len);

void parser_finish();

int parseCmdlineAndProcInput(int argc, char* argv[]);
