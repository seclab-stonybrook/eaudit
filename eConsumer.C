/*******************************************************************************
 *  Copyright 2022-23 R. Sekar and Secure Systems Lab, Stony Brook University
 *******************************************************************************
 * THIS IS PROPRIETARY SOFTWARE. ALL RIGHTS RESERVED.
 ********************************************************/
// We moved to running the consumer online at data collection time. This
// will allow us to query the OS for all the missing pieces of info. We need
// some invariants to proceed: (a) subject needs to be auto created or updated
// by querying the OS *before* it can execute any syscalls. Fields such as cwd
// should be reliable.
//

#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <string.h>
#include <unistd.h>
#include <cstring>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <sstream>

#include "STLutils.h"
#include "MFUTab.h"
#include "Histogram.h"

#include "eauditk.h"
#include "prthelper.h"

#include "eClient.h"
#include "eConsumer.h"
#include "eRecorder.h"

// A bunch of variables to maintain statistics on events and timestamps that
// should help track potential problems. Also some external functions to
// pretty-print this information.

LongHistogram searchlen, dqlen, oldEvTimeDiff, oohg;

extern string countReadable(long, int);
static long nsubj, npresubj, nprocs, nthreads, nchildret;

extern const char* scname[256];
long succ_count[256], fail_count[256], err_type[256];

static long nresolved, nunresolved, uncounted_unres, nfforced, nfmissing, 
   nffound, nunspecep, nnetlinkep, ninetep, ninet6ep, nlocalep, nerrorep; 
   //nunkrms;

static long procopen, procopenerr, procopenerr1, procopenerr2, procreaderr, 
   piderr, staterrs, procfderr, statquery, procfdquery;

static long noutoforder, nmajoroo, noutofseq, 
   nforced_earlier, nfailed, nsucc, nreadwr;
static long tooLateEvent, tooEarlyEvent, ncollisions, nbadcollisions;
static long injected_clone_entries, clones_wo_returns, expired_events;

LookupOpt fileopt, procopt;

#define update_nfailed(rv)    if (is_err(rv)) nfailed++; else nsucc++
static void update_fail_count(uint8_t sc, long ret) {
   fail_count[sc]++;
   if (-255 < ret && ret < 0)
      err_type[-ret]++;
}
extern const char* errcode[];

/******************************************************************************
 * eConsumer has the following main tasks:
 *
 *   1. Maintain some minimal information about subjects and objects
 *      respectively in SubjInfo and Obj classes. For both subjects and
 *      objects, it maintains the corresponding InstId assigned by eRecorder.
 *      (If eRecorder is not present, eConsumer assigns id's itself.) The info
 *      SubjInfo and Obj are the kinds of information reported with some
 *      syscalls but may possibly be needed later while processing another
 *      syscall that does not report this information. Often, more infor about
 *      objects and subjects is available if we lookup /proc, and if that is
 *      enabled, eConsumer includes that in Subj/Obj.
 *
 *      In most cases, we use MFU tables for maintaining information. This
 *      approach avoids some potential sources of memory leaks, and places a
 *      specific upper bound on memory utilization. However, the string table
 *      grows monotonically and is a source of memory leak. CONSIDER REPLACING
 *      w/ ref-counted strings and intelligent Id maps that reuse freed indices.
 *
 *   2. Pair syscall entries with exits. Because of buffering on different
 *      cores, and since the entry and exit of the same syscall may execute on
 *      different cores, we may see the exits before entries. Secondly, some
 *      information (e.g., most arguments) is available at the entry event,
 *      while others (return values and return parameters) are available only at
 *      the exit event. For each subject, eConsumer keeps track of the entry and
 *      exit events, and matches them up. It also tries to handle cases where
 *      the entry or the exit may be lost. 
 *
 *      Note that there is no foolproof way to match entry and exits here: if we
 *      have multiple instances of the same system calls in transit, our logic
 *      may end up mismatching them. This error can be avoided if (a) matching
 *      is done in the kernel, or if (b) the enters and exits have high weights
 *      in eAudit, causing them to transmitted to the user level as soon as the
 *      kernel sees them. This is the current path forward. Almost all syscalls
 *      will be logged only at the exit, with the kernel matching up the entry
 *      and exit. The only exceptions are security-critical syscalls such as
 *      kill, and special syscalls such as clone and execve. These are rare
 *      enough that we can apply (b). These changes should be in place soon.
 *
 *   3. Order system calls using sequence numbers (when available) and
 *      timestamps. Once system call entries have been matched up with exits,
 *      they are put on a global event queue. Syscalls stay on this queue until
 *      we are reasonably confident that we have all preceding syscalls, and at
 *      this point, the syscall is processed using doXX calls, where XX is the
 *      system call name. A doXX call updates various data structures maintained
 *      by eConsumer to reflect the effect of executing this system call, and
 *      then invokes the system call on Host. Note, again, that we cannot
 *      guarantee correct ordering in all cases.
 *
 *      Multiple options are possible for queuing and dequeuing. The base
 *      algorithm uses sorting based on timestamps, and hence has nontrivial
 *      overhead for serialization (This is despite significant effort spent in
 *      optimizing this algorithm.) The second algorithm, activated when
 *      USE_SEQNUM ifdef is set, is the default now. It uses sequence numbers,
 *      but accommodates non-unique sequence numbers. (eAudit's logic ensure
 *      that sequence numbers are atomically incremented, so the range of
 *      sequence numbers used will match the number of syscalls. But that does
 *      not rule out the possibility that multiple syscalls will report the same
 *      sequence number.) Because of this, it is less efficient than a simpler
 *      algorithm that assumes uniqueness, but is still much faster than the
 *      timestamp based algorithm. It is also much better at correctly ordering
 *      near-simultaneous events.
 *
 *   4. Maintain the list of clients interested in syscalls, and deliver each
 *      syscall to them using the corresponding method in eClient interface.
 *      Delivery occurs from the doXX methods.
 *
 *      eRecorder, if present, should also implement the eClient interface.
 *      MOREOVER, it should be passed as an argument to the constructor, as (i)
 *      eConsumer will uses its string table, and (ii) eConsumer must assign
 *      object and subject ids's if eRecorder is not present. Finally, eRecorder
 *      should not register as a client.
 ******************************************************************************/

uint64_t maxts_;  // Max. timestamp seen so far, incl events not executed.
uint64_t last_compl_ts_; // Timestamp of last completed (i.e., dequeued and
                         // processed, aka "executed") event.

#define CLK_ERR 50 // Max error we have observed in TS of closely spaced events

///////////////////////////////////////////////////////////////////////////////
//          First, define SubjInfo, Obj and related MFU Tables           //
///////////////////////////////////////////////////////////////////////////////

class SubjInfo;

MFUSet<StrId> ePs(64000);
MFUTable<long, SubjInfo*> procMap(32000); // Maps SubjInstId to SubjInfo
MFUTable<long, StrId> id2nm_map(1024*1024);  // Maps eaudit id to Object name
MFUTable<StrId, Obj*> nm2oi_map(128000, true); // Maps object name to Obj

struct SubjInfo: public Subj {
   bool definite_orphan; // we never saw a clone entry or exit for this tid.
   uint64_t lastEvTime; // To force parent's clone is processed before child's
   uint64_t exitTime;   // Don't queue events after this time.
   vector<EventInfo*> curEv;

   // Used to create skeleton subjects
   SubjInfo(SubjInstId s, int tid_, int pid_, int ptid_, 
            int uid_, int gid_, uint64_t ts, bool is_orph):
      Subj(s.id(), tid_, pid_, ptid_, uid_, gid_), 
      definite_orphan(is_orph), lastEvTime(ts), exitTime(~(0ul)), curEv() {
     nsubj++; 
   };

  // Used to create SubjInfo of threads. Most info is shared with parent, so 
  // the number of parameters passed into this constructor is minimal.
  SubjInfo(int tid_, const SubjInfo* par, uint64_t ts_, bool is_orphan):
        Subj(par->id, tid_, par->pid, par->tid, par->uid, par->gid), 
        lastEvTime(ts_), exitTime(~(0ul)), curEv() {
     setcwd(par->cwd);
     setexe(par->exe);
     cloneargs(par->args);
     cloneenvs(par->envs);
     nsubj++; 
  }

  // Used in clone
  SubjInfo(const SubjInfo& si): Subj(si), definite_orphan(si.definite_orphan),
               lastEvTime(si.lastEvTime), exitTime(si.exitTime), curEv() {
     cwd = 0; exe = 0; args = 0; envs = 0; argv_ = 0; envp_ = 0;
     setcwd(si.cwd);
     setexe(si.exe);
     cloneargs(si.args);
     cloneenvs(si.envs);
     nsubj++;
  }

  // Most objects are created in nm2objinfo and reside in an MFU. As they are
  // subject to eviction, we cannot store pointers to them here, but must make
  // a copy. A downside of a copy is that the object may get updated (by chmod
  // or stat) and cwd/exe won't reflect that. We ignore this concern for now.
  // (Plus, there maybe a case for leaving info as of the time exe/cwd was set.)

  void setcwd(const Obj* o) {
     delete cwd;
     cwd = new Obj(*o);
  }

  void setexe(const Obj* o) {
     delete exe;
     exe = new Obj(*o);
  }

  ~SubjInfo() {
     curEv.clear();
     delete [] args;
     delete [] envs;
     delete [] argv_;
     delete [] envp_;
     delete cwd;
     delete exe;
  }
};

///////////////////////////////////////////////////////////////////////////////
//           Helpers to translate between StrId and const char*              //
///////////////////////////////////////////////////////////////////////////////

static ERecorder* erecorder_;
static IdMap<StrId, const char *> strtab_;
static unordered_map<const char *, StrId> strmap_;

StrId create(const char* s)  {
   if (erecorder_)
      return erecorder_->create(s);

   if (!s)
      return StrId();

   //   s = ""; // Let us treat a null pointer as empty string
   auto it = strmap_.find(s);
   if (it != strmap_.end())
      return it->second;

   unsigned n = strlen(s) + 1;
   char *s1 = new char[n];
   strncpy(s1, s, n);
   auto rv = strtab_.alloc();
   strtab_[rv] = s1;
   strmap_[s1] = rv;
   return rv;
};

static const char* str(StrId i) {
   if (erecorder_)
      return erecorder_->str(i);

   return (i == StrId::null()) ? "" : strtab_[i]; // strtab_ checks bounds.
}

static StrId* copyargv(const char* const* argv) {
// Enters argv strings into strtab_ so that their values are copied, and
// we have safe pointers to them. 

   unsigned n=0; 
   if (argv)
      while (argv[n])
         n++;

   StrId* rv = new StrId[n+1];
   for (unsigned j=0; j < n; j++)
      rv[j] = create(argv[j]);

   return rv;
}

static StrId* mkargv(const char* s, unsigned totsize) {
// s contains a *sequence* of null-terminated strings, with total length given
// by totsize. We copy these strings into strtab and create a conventional argv.

   const char* p = s;
   const char* r = p;
   const char* q = p+totsize;
   unsigned n=0;
   for (; r < q; r++) {
      if (!*r) n++;
      if (n >= MAX_ARG-1) break; // limit from eauditk.h
   }
   // Invariant: (r < q && *r = '\0') || (r == q)

   StrId* rv = new StrId[n+1];
   unsigned j=0;
   while (p < r) {
      unsigned l = strnlen(p, q-p);
      // Strangely, we read a very long sequence of null bytes from /proc that
      // leads to the creation of needless args or env vars. Skip them here.
      if (l > 0)
         rv[j++] = create(p);
      p += l+1;
   }

   return rv;
}

static int nargs(const StrId* sv) {
   unsigned n=0;
   for (; sv && !sv[n].isNull(); n++);
   return n;
}

static const char* const* getargv(const char* const* &argv, const StrId* args) {
   if (!argv) {
      unsigned n = nargs(args);
      auto av = new const char*[n+1];
      for (unsigned j=0; j < n; j++)
         av[j] = str(args[j]);
      av[n] = nullptr;
      argv = av;
   }
   return argv;
}

static void clone_args(const StrId* sv, const StrId* &args) {
   unsigned n = nargs(sv);
   if (args)
      delete [] args;
   auto as = new StrId[n+1];
   for (unsigned j=0; j < n; j++)
      as[j] = sv[j];
   args = as;
}

int Subj::argc() const { return nargs(args); }
int Subj::envc() const { return nargs(envs); }

const char* const* Subj::argv() const { return getargv(argv_, args); }
const char* const* Subj::envp() const { return getargv(envp_, envs); }

void Subj::cloneargs(const StrId *a) { clone_args(a, args); };
void Subj::cloneenvs(const StrId *e) { clone_args(e, envs); };

const char* Obj::name() const { return str(nm); };

///////////////////////////////////////////////////////////////////////////////
//           Helper functions that look up /proc when we don't have          //
//           any information on a file descriptor or a subject.              //
///////////////////////////////////////////////////////////////////////////////

static const int PBUFL = 1<<16;
static char pbuf[PBUFL];
static char *pbuf_next = pbuf;

static void
staterr(const char* f) {
   staterrs++;
   if (errno != ENOENT) // Common error: count their #, skip warn msg.
      warnPrtf("Stat failed on file %s: %s\n", f, strerror(errno));
}

static inline void
reset_pbuf() {
   pbuf_next = pbuf;
}

static inline int
rem_spc_pbuf() {
   return &pbuf[PBUFL] - pbuf_next - 8; // 8 for additional error margin
}

char *advance_pbuf(int nr, const char* fn, const char* arginfo) {
   if (nr > 0) {
      assert_abort(rem_spc_pbuf() > nr);
      char* rv = pbuf_next;
      pbuf_next[nr] = '\0';
      pbuf_next += nr+1;
      return rv;
   }
   char em[512];
   snprintf(em, sizeof(em), "%s: %s: %s", fn, arginfo, strerror(errno));
   errPrtf("%s\n", em);   
   return nullptr;
}

static inline char*
copy2buf(const char* src, int len, char term) {
   char *rv = pbuf_next;
   assert_abort(rem_spc_pbuf() > len);
   memcpy(pbuf_next, src, len);
   pbuf_next += len-1;
   if (*pbuf_next != term) {
      if (*pbuf_next == '\0')
         *pbuf_next = term;
      else {
         pbuf_next++;
         *pbuf_next = term;
      }
   }
   pbuf_next++;
   return rv;
}

static int
openProc(int tid) {
   char b[32];
   snprintf(b, sizeof(b), "/proc/%d", tid);
   auto rv = open(b, O_RDONLY);
   return rv;
}

static char *
getProcFile(int dirfd, const char* file, ssize_t* len=nullptr) {
   int fd = openat(dirfd, file, O_RDONLY);
   if (fd >= 0) {
      ssize_t nr = read(fd, pbuf_next, rem_spc_pbuf());
      if (len)
         *len = nr;
      close(fd);
      return advance_pbuf(nr, "getProcFile", file);
   }
   return nullptr;
}

static char *
getProcLink(int dirfd, const char* file) {
   int nr = readlinkat(dirfd, file, pbuf_next, rem_spc_pbuf());
   return advance_pbuf(nr, "getProcLink", file);
}   

static char *
getFdLink(int tid, int fd, char* buf, size_t l) {
   char b[64];
   snprintf(b, sizeof(b), "/proc/%d/fd/%d", tid, fd);
   int nr = readlink(b, buf, l-1);
   if (nr >= 0) {
      buf[nr] = '\0';
      return buf;
   }
   else if (errno != ENOENT) // Common error, skip warn msg.
      warnPrtf("readlink(%s) failed: %s\n", b, strerror(errno));
   return nullptr;
}   

static bool
getProcStatus(int procfd, int& pr_tgid, 
              int& pr_pid, int& pr_ppid, int& uid, int &gid) {
   // Can (and should) get supplementary groups from "Groups: "

   char *b = getProcFile(procfd, "status");
   if (!b) return false;
   if (!(b = strcasestr(b, "tgid:"))) return false;
   if (sscanf(b + sizeof("tgid:"), "%d", &pr_tgid) != 1) return false;
   if (!(b = strcasestr(b, "pid:"))) return false;
   if (sscanf(b+sizeof("pid:"), "%d", &pr_pid) != 1) return false;
   if (!(b = strcasestr(b, "ppid:"))) return false;
   if (sscanf(b+sizeof("ppid:"), "%d", &pr_ppid) != 1) return false;
   if (!(b = strcasestr(b, "uid:"))) return false;
   if (sscanf(b+sizeof("uid:"), "%d", &uid) != 1) return false;
   if (!(b = strcasestr(b, "gid:"))) return false;
   if (sscanf(b+sizeof("gid:"), "%d", &gid) != 1) return false;
   return true;
}

///////////////////////////////////////////////////////////////////////////////
//                     EConsumer Constructor and Destructor                  //
///////////////////////////////////////////////////////////////////////////////

const int initd=1;
const int root=0;
const int rootg=0;
const SubjInstId initSid(0);

EConsumer::
EConsumer(bool lookupProc, bool prtFiles, bool prtEP, 
          bool sortByFreq, ERecorder* eh): 
               prtFiles_(prtFiles), prtEP_(prtEP), 
               sortByFreq_(sortByFreq), curtime_(0)  {
   erecorder_ = eh;
   if (lookupProc) 
      fileopt = procopt = QUERY_OS;
   else fileopt = procopt = CREATE_BEST_EFFORT;
   uint64_t boottime =  (uint64_t)(1657825670*1e9);
   SubjInfo* initp = new SubjInfo(initSid, initd, initd, initd, ::root, rootg, 
                                    boottime, true);
   initp->setcwd(nm2Obj(initp, create("/"), boottime, 
                        NmOpt(OLD, FILET, fileopt)));
   initp->setexe(nm2Obj(initp, create("/initd"), boottime, 
                        NmOpt(OLD, FILET, fileopt)));
   procMap.insert(initd, initp, true /*pinned entry, never removed*/);
   last_compl_ts_ = 0;

   if (erecorder_) {
      clients_.push_back(erecorder_);
      own_.push_back(true);
   }
}

EConsumer::
~EConsumer() {
   for (unsigned j=0; j < clients_.size(); j++)
      if (own_[j])
         delete clients_[j];

   procMap.removeAndDestroyAll();
   id2nm_map.removeAll();
   nm2oi_map.removeAll();
   ePs.removeAndDestroyAll();
   while (!freeEv_.empty()) {
      delete freeEv_.top();
      freeEv_.pop();
   }
}

void EConsumer::
enroll(EClient* c, bool take_ownership) {
   if (c != erecorder_) {
      clients_.push_back(c);
      own_.push_back(take_ownership);
   }
}

const char* 
EConsumer::str(StrId i) const {
   return ::str(i);
}

///////////////////////////////////////////////////////////////////////////////
//              Helper functions to lookup and/or create SubjInfo            //
///////////////////////////////////////////////////////////////////////////////

SubjInfo* EConsumer::
getSubj(int tid, int pid, uint64_t ts, int uid, int gid) {
// Look up SubjInfo --- create a skeleton SubjInfo if it does not exist.

  auto rv = procMap.lookupData(tid);
  if (!rv) {
    rv = new SubjInfo(SubjInstId(), tid, pid, 1, uid, gid, ts, true);//skeleton
    // procMap.insert(tid, rv);
    procMap.update(tid, rv);
  }
  return rv;
}

static SubjInfo*
mkProperThread(int tid, SubjInfo* prsi, uint64_t ts) {
   SubjInfo* chsi = procMap.lookupData(tid);
   if (!chsi) {
      chsi = new SubjInfo(tid, prsi, ts, true); // thread
      // procMap.insert(chsi->tid, chsi);
      procMap.update(chsi->tid, chsi);
   }
   else chsi = new (chsi) SubjInfo(tid, prsi, ts, true); // thread
   return chsi;
}

// If we missed the clone return, then we may have no way to know the parent. In
// this case, the following function will create a preexisting subject on Host.
// 
// Obviously, we want to avoid the creation of preexisting subjects, as it leads
// to a loss of accuracy (no parent, missing uid/gid, etc.). One way to overcome
// this loss is by looking up /proc. This is pretty much foolproof --- it can
// fail if the query to /proc is too late, but this is unlikely in practice:
// unknown subjects are still running but were spawned before logging began.
//
SubjInfo* EConsumer::
createExistingSubj(int tid, int pid, uint64_t ts, LookupOpt opt) {
   SubjInfo* prsi = nullptr;
   int uid=0, gid=0;
   int pr_tgid = pid, pr_pid = tid, pr_ppid = 0;
   const char *cwd=0, *exe=0, *argv=0, *env=0;
   ssize_t argvlen, envlen;
   bool openerr=false;

   bool ids_read = false;
   bool strings_read = false;
   int pids_ptid=0;
   int lasterr=0;

   if (opt == QUERY_OS) {
     reset_pbuf();
     int procfd = openProc(tid);
     procopen++;
     if (procfd >= 0) {
       if (getProcStatus(procfd, pr_tgid, pr_pid, pr_ppid, uid, gid)) {
         if (pr_tgid != pid) {
           piderr++;
           pid = pr_tgid;
         }
         ids_read = true;
       }
     }
     else lasterr = errno;

     if (pid != tid) {
        int procfd1 = openProc(pid);
        if (procfd >= 0 && procfd1 < 0) {
           // Shd be rare, so OK to print a message.
           errPrtf("Opened /proc/tid but not /proc/pid: tid=%d, pid=%d\n",
                   tid, pid);
           procopenerr1++;
           openerr = true;
        }
        else if (procfd1 >= 0) {
           // For short-lived threads, proc lookup on the tid can fail but pid
           // lookup (of the thread/process grp) may work. This seems reasonable
           // if (lasterr > 0) // so let us not print an err msg.
           //   warnPrtf("Opened /proc/pid but not /proc/tid: tid=%d, pid=%d\n",
           //        tid, pid);
           procopenerr2++;
           // This error seems too common, so we disabled printing it. 
           // openerr = true;
           ::close(procfd);
           procfd = procfd1;
        }
     }

     if (procfd >= 0) {
        if (!ids_read) 
           if (getProcStatus(procfd, pr_tgid, pr_pid, pids_ptid, uid, gid))
              ids_read = true;
        // An alternative is to always read /proc/pid/status but if we already
        // have the same info from /proc/tid/status, why bother. 

        cwd =  getProcLink(procfd, "cwd");
        exe =  getProcLink(procfd, "exe");
        argv = getProcFile(procfd, "cmdline", &argvlen);        
        env = getProcFile(procfd, "environ", &envlen);

        ::close(procfd);
        strings_read = cwd && exe && argv && env;
        if (!strings_read || !ids_read)
           procreaderr++;
     }
     else {
        if (!openerr) // i.e., neither of procopenerr{1,2} are flagged.
           procopenerr++;
        warnPrtf("Open /proc/%d failed: %s\n", tid, strerror(lasterr));
     }
   }  // Done querying the OS for subject info

   prsi = getSubj(pid, pid, ts);
   if (ids_read) {
      if (pid == tid)
         prsi->ptid = pr_ppid;
      else if (pids_ptid)
         prsi->ptid = pids_ptid;
      prsi->uid = uid;
      prsi->gid = gid;
   }

   prsi->setcwd(nm2Obj(prsi, create(cwd), ts, NmOpt(OLD, FILET, fileopt)));
   prsi->setexe(nm2Obj(prsi, create(exe), ts, NmOpt(OLD, FILET, fileopt)));
   if (strings_read) {
      prsi->args = mkargv(argv, argvlen);
      prsi->envs = mkargv(env, envlen);
   }

   if (prsi->id == nullsiid.id()) {
      // Indicates that the subject hasn't been created, do it now.
      prsi->definite_orphan = true;
      npresubj++;
      if (!erecorder_)   // In this case, eConsumer shd generate the subject id 
         prsi->id = nsubj;
      else prsi->id = erecorder_->existingSubj(prsi, ts);

      for (auto cli: clients_)
         if (cli != erecorder_)
            cli->existingSubj(prsi, ts);
   }

   // prsi must point to a full subject now.
   if (tid != pid)
      return mkProperThread(tid, prsi, ts);
   else return prsi;
}

/*******************************************************************************
 * Helpers to convert endpoints to Host format and a few addl. ones for printing
 ******************************************************************************/

inline static char
hexdigit(char c) {
   if (0 <= c && c < 10)
      return '0'+c;
   else return 'a' + (c-10);
}

inline static void
bin2str(char *s, const char* path, size_t len) {
// Helper function used by getEP: converts non-ascii chars to printable form
  for (unsigned j=0; j < len; j++) {
    if (isascii(path[j]))
      *s++ = path[j];
    else {
      sprintf(s, "\\x%c%c", hexdigit((path[j]>>4)&0xf), hexdigit(path[j]&0xf));
      s += 4;
    }
  }
  *s = '\0';
}

#define UNIX_PATH_MAX    108 // This is long-standing limit on the max length of
               // UNIX-domain sockets, but could not find the right include file

// To get the list of local IP4 addresses, use the following command:
// echo $(cat /proc/net/fib_trie| awk '/32 host/ { print f} {f=$2}'| sort -u)
// For IP6 addresses, use: cat /proc/net/if_inet6 | awk '{print $1}'

// @@@@ Does Host really need us to distinguish between local, enterprise and
// @@@@ remote addresses? Note that eaudit marks IP4/IP6 to be local because
// @@@@ it does not maintain info about host's IP addresses. We can fix this
// @@@@ here. If we do, we should return this info in another parameter, and 
// @@@@ subsequently, store this info in Obj so every client can use it
// @@@@ including Host. But until we know it is needed, we will default to 
// @@@@ reporting all IPs as remote to Host.

StrId EConsumer::
getEp(const uint8_t *sa, int salen) {
  const char* rv = "invalid";
  if (salen >= (int)sizeof(sa_family_t)) {
    saddr_t& saddr = *(saddr_t*)sa;
    char s[1024]; char *p = s;
    rv = s; s[0] = '\0';
    switch (saddr.sun.sun_family) {
    case AF_LOCAL: {
      const struct sockaddr_un& un = saddr.sun;
      nlocalep++;
      strcpy(p, "unix:"); p += 5;
      if (salen == sizeof(sa_family_t))
        strcpy(p, "unnamed");
      else if (un.sun_path[0] == '\0')
        // These are special endpoints that don't create a file. 
        bin2str(p, un.sun_path, ::min(salen-sizeof(sa_family_t), 
                                      sizeof(s)/4-10));
      else {
        strncpy(p, un.sun_path, min(UNIX_PATH_MAX, salen-2));
        p[min(UNIX_PATH_MAX, salen-2)] = '\0';
      }
      break;
    }

    case AF_INET: {
      ninetep++;
      strcpy(p, "IP4:"); p += 4;
      getnameinfo((struct sockaddr*)&saddr.sin, sizeof(saddr.sin), 
                  p, sizeof(s)-4, nullptr, 0, NI_NUMERICHOST);
      sprintf(p+strlen(p), ":%d", ntohs(saddr.sin.sin_port));
      break;
    }

    case AF_NETLINK: {
      nnetlinkep++;
      const struct sockaddr_nl& nl = saddr.snl;
      sprintf(p, "netlink:%d/%x", nl.nl_pid, nl.nl_groups);
      // @@@@ Netlink socket port 0 causes spurious flows. We should DISABLE
      // @@@@ them by DROPPING the relevant syscalls. We can't fix it here.
      break;
   }

   case AF_INET6: {
      ninet6ep++;
      strcpy(p, "IP6:"); p+= 4;
      getnameinfo((struct sockaddr*)&saddr.sin6, sizeof(saddr.sin6), 
                  p, sizeof(s)-4, nullptr, 0, NI_NUMERICHOST);
      sprintf(p+strlen(p), ":%d", saddr.sin6.sin6_port);
      break;
   }

   default:
      break;
   }
  }

  auto ret =  create(rv);
  ePs.insert(ret);
  return ret;
}

/*******************************************************************************
 * Helper functions to lookup and/or create Obj
 ******************************************************************************/

// @@@@ We are trying to maintain a name -> objinfo mapping, which requires
// @@@@ accurate tracking of changes to the file system. This may be inherently
// @@@@ hard; even otherwise, the task seems tricky enough to introduce bugs.
// @@@@ We need ways to track the errors we are making. For instance, are
// @@@@ multiple id's mapping to the same name? Or multiple files with same id?
// @@@@ Neither is an error, but if the number of such instances is significant,
// @@@@ it may indicate bugs. UNFORTUNATELY, we are not maintaining any stats
// @@@@ that will alert us to the possibility of such errors.


// We have two maps: id -> nm, and nm -> objinfo, with the following main fns:
//   1. nm2Obj is to used to look by name and create objinfo if not present.
//      It will also update id2nm map.
//   2. resolveId which does an id->name lookup and name->objinfo lookup. Since
//      it uses nm2Objnfo, it shares the latter's guarantee on its ouput.
//   3. fullpath is used in the context of "at" syscalls to compute the full
//      path name. In the contexts where it is used, we don't have id (or any
//      stat info), so nothing is done to either of the maps.
//   4. nm2ObjAt is used in the context of "at" syscalls where we need
//      Obj, so after using fullpath, whatever info we have is entered
//      into the two maps (by calling nm2Obj).

Obj* EConsumer::
nm2Obj(SubjInfo* si, StrId nm, uint64_t ts, NmOpt opt, uint64_t id) {
// Look up Obj by name (in nm2oi_map). If it does not exist:
//   (a) if opt==QUERY_OS and otype==FILE, use stat to look up perm, mtime etc.
//   (b) create Obj with available info and insert into nm2oi_map.
//   (c) report existingObj to all clients.
// NOTE: an Obj is always created if needed, so return value is never NULL.
// NOTE: id2nm_map is also updated if id is non-null.

   unsigned mtime=0;
   int mode = 0644;
   int uid = 0;
   int gid = 0;
   Obj* rv = nm2oi_map.lookupData(nm);
   if (!rv || (id != nullid && rv->id != id)) {
      // We don't have a mapping for the name, or the mapping is clearly wrong
      if (opt.opt == IGNORE)
         nfmissing++;
      else {
         if (opt.opt == QUERY_OS && opt.otype == FILET) {
            statquery++;
            struct stat sbuf;
            const char* nam = str(nm);
            if (stat(nam, &sbuf) < 0)
               staterr(nam);
            else {
               mode = sbuf.st_mode & 07777; // Last 12 bits are the perm bits;
               uid = sbuf.st_uid;
               gid = sbuf.st_gid;
               mtime = sbuf.st_mtime;
               if (opt.create_flag==MAYBE_NEW) {
                  if (si->uid == uid && si->gid == gid &&
                      sbuf.st_atime == sbuf.st_ctime &&
                      sbuf.st_ctime == sbuf.st_mtime &&
                      labs(long(sbuf.st_mtime) - curtime_) < 5)
                     opt.create_flag = NEW;
                  else opt.create_flag = OLD;
               }
               // @@@@ This is unreliable. We should use statx to get btime
               // @@@@ and then this may provide reasonable accuracy. (But we
               // are hoping it would be OK because we have the added evidence
               // that this is the first time we are hearing about this file.
            }
         }

         nfforced++;
      }

      if (opt.otype != FILET) {
         uid = si->uid;  gid = si->gid; mode = 06666;
      }
      auto oo = new Obj(nm, (ObjType)opt.otype, id, uid, gid, mode, mtime);
      // nm2oi_map.insert(nm, oo);
      nm2oi_map.update(nm, oo);
      rv = nm2oi_map.lookupData(nm);
      assert_abort(oo == rv);
      if (opt.otype == FILET && opt.create_flag != NEW)
            for (auto cli: clients_)
               cli->existingObj(si, rv, ts);
      // Note: Not meaningful to say that a pipe or socket is preexisting.
   }
   else nffound++;

   if (id != nullid) {
      id2nm_map.update(id, nm);
      // If it is a new use 
      if (rv->id != id) {
         rv->id = id;
         rv->oid = nulloiid_i;
      }
   }
   return rv;
}

Obj* EConsumer::
createSocket(SubjInfo* si, uint64_t id, StrId remEp, uint64_t ts) {
   return nm2Obj(si, remEp, ts, NmOpt(NEW, SOCKETT, fileopt), id);
}

StrId EConsumer::
createObjNmAsStr(SubjInfo* si, int fd, uint64_t id) {
   char s[128];
   sprintf(s, "id_%lu", id);
   return create(s);
}

static ObjType id2otype(uint64_t id) {
   if (id == nullid || isfile(id)) return FILET;
   else if (ispipe(id)) return PIPET;
   else return SOCKETT;
}

Obj* EConsumer::
resolveId(SubjInfo* si, int fd, long id, uint64_t ts, NmOpt opt) {
// Return is non-null if id is non-null: Obj is created, but may contain
// no useful info (just default values), depending on parameters supplied here.

   Obj* rv;
   StrId nm = id2nm_map.lookupData(id);
   if (id != nullid)
      opt.otype = id2otype(id);

   if (nm.isNull()) {
      if (opt.opt == QUERY_OS) {
         procfdquery++;
         char fnstore[2048];
         char *fn = getFdLink(si->tid, fd, fnstore, sizeof(fnstore));
         if (fn)
            nm = create(fn);
         else procfderr++;
      }
      if (nm.isNull())
         nm = createObjNmAsStr(si, fd, id);

      if (id != nullid)
         id2nm_map.update(id, nm);
   }

   // nm is non-null
   rv = nm2Obj(si, nm, ts, opt, id);
   return rv;
}

StrId EConsumer::
fullpath(SubjInfo *si, int at_fd, uint64_t at_id, StrId fn, 
         uint64_t ts, NmOpt opt) {
// Compute full path to be used for openat-like operations. 

   StrId rv, dir;
   const char* nm = str(fn);
   if (*nm == '/') // NOTE: fd/id applies ONLY if fn DOES NOT start with a "/"
      return fn;
   else {
      if (at_fd == AT_FDCWD)
         dir = si->cwd->nm;
      else dir = resolveId(si, at_fd, at_id, ts, opt)->nm;

      const char* s = str(dir);
      size_t slen = strlen(s);
      size_t nmlen = strlen(nm);
      char *fullnm = (char*)alloca(slen+nmlen+1);
      memcpy(fullnm, s, slen);
      char *p = fullnm+slen;
      if (p > fullnm && *(p-1) == '/') p--;
      *p++ = '/';
      memcpy(p, nm, nmlen);
      p[nmlen] = '\0';
      auto rv = create(fullnm);
      return rv;
   }
}

Obj* EConsumer::
nm2ObjAt(SubjInfo* si, int at_fd, long at_id, StrId nm, uint64_t ts, NmOpt opt,
         uint64_t id) {
   StrId fnm = fullpath(si, at_fd, at_id, nm, ts, 
                        NmOpt(OLD, FILET, fileopt));
   return nm2Obj(si, fnm, ts, opt, id);
}

/*******************************************************************************
 * On to the core of eConsumer, which consists of two sets of functions. The
 * first set is for queueing system calls, and the second for executing them.
 * Most syscalls are reported at their exit point by the current version of
 * eAudit, and have all the parameter and return code available at this point.
 * So, they can be queued right away. For a few system calls, such as execve,
 * fork and mmap, entry and exit events are reported separately. In these cases,
 * we need to match the entry and exit, while accounting for the possibility
 * that the exit arrives here before the entry. We use preOp, ent_XX and
 * sc_exit/exit_YY for the second class of syscalls. The first class uses
 * prePostOp and XX. (Here, XX stands for a syscall name.)
 ******************************************************************************/

// Find the best matching event. A function dist() defines distance between an
// existing event e1 and a new event e2 under construction as the difference
// between sequence numbers *if* the event types match. Now best_matching_event
// picks the min based on dist. Note that this is still best effort: there is no
// guarantee that we will find the right match. For instance, the actual
// sequence may be entry1 exit1 entry2 exit2 but because of caching, exit1 and
// entry2 may be delayed. We will incorrectly match entry1 with exit2. There is
// simply no way to detect an error has even happened. (At least not unless we
// revisit events that are already in the queue q_. So, we accept this best
// effort approach. Stronger guarantees can be obtained using means (a) and (b)
// discussed earlier.)
//
static uint16_t sndiff(uint16_t sn1, uint16_t sn2) {
   //int rv = min(sn1-sn2, sn2-sn1);
   return abs(((int)sn1) - ((int)sn2));
}

static bool too_old(uint16_t sn1, uint16_t sn2) {
   return (sndiff(sn1, sn2) > 65535/4);
   // This ensures that unmatched events are "timed out" soon enough to be
   // executed in the order of their sequence number.
}

static bool too_old(uint64_t old_ts, uint64_t cur_time) {
   constexpr unsigned maxt = 1000*1000*1000; 
   // 1 second seems soon enough: 2 seconds is the default in the event queue
   return (old_ts < cur_time && cur_time - old_ts > maxt);
}

static unsigned
dist(const EventInfo e1, char e2_code, uint16_t e2_sn, SysCallStat e2_stat) {
   unsigned rv = INT_MAX;
   if ((e1.ev_code == e2_code) &&
       ((e1.status == ENTRY_SEEN && e2_stat == EXIT_SEEN) ||
        (e2_stat  ==  ENTRY_SEEN && 
                  (e1.status == EXIT_SEEN || e1.status == INJECTED_EXIT))))
      rv = sndiff(e1.seqnum, e2_sn);
   return rv;
}

static
int best_matching_event(vector<EventInfo*>& e, char sc, uint16_t sn, 
                        SysCallStat entry_or_exit, uint64_t cur_time, 
                        vector<EventInfo*>& expired) {
   int rv = -1; unsigned best_match = INT_MAX;

   for (unsigned j=0; j < e.size(); j++) {
      unsigned newdist = dist(*e[j], sc, sn, entry_or_exit);
      if (newdist < best_match) {
         rv = j;
         best_match = newdist;
      }
      else if (too_old(e[j]->seqnum, sn) || too_old(e[j]->ts, cur_time)) {
         expired.push_back(e[j]);
         swap(e[j], e[e.size()-1]);
         e.pop_back();
         j--;
      }
   }
   return rv;
}


SubjInfo* EConsumer::
preOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int& idx) {
   SubjInfo* si = getSubj(tid, pid, ts); // Always non-null.

   vector<EventInfo*> expired;
   reset_pbuf();
   idx = best_matching_event(si->curEv, sc, sn, ENTRY_SEEN, curtime_, expired);
   processExpired(expired);

   if (idx == -1) {
      si->curEv.push_back(newEvInfo());
      idx = si->curEv.size()-1;
      si->curEv[idx]->status = ENTRY_SEEN;
      si->curEv[idx]->ev_code = sc;
      si->curEv[idx]->si = si;
      si->curEv[idx]->seqnum = sn;
      si->curEv[idx]->ts = ts;
      si->curEv[idx]->arg[3].l = 0; // default return value
   }
   else si->curEv[idx]->status = BOTH_SEEN;

   return si;
}

SubjInfo* EConsumer::
prePostOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long rv, 
          int& idx) {
   SubjInfo* si = getSubj(tid, pid, ts); // Always non-null.
   reset_pbuf();
   si->curEv.push_back(newEvInfo());
   idx = si->curEv.size()-1;
   si->curEv[idx]->status = BOTH_SEEN;
   si->curEv[idx]->ev_code = sc;
   si->curEv[idx]->si = si;
   si->curEv[idx]->seqnum = sn;
   si->curEv[idx]->ts = ts;
   si->curEv[idx]->arg[3].l = rv; 

   update_nfailed(rv);
   return si;
}

void EConsumer::
accRcvfPeer(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
            long id, const uint8_t *saddr, unsigned salen, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = getEp(saddr, salen);
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
bind(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
     const uint8_t *saddr, unsigned salen, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = getEp(saddr, salen);
   enq(si, idx);
}

void EConsumer::
chdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, const char* fn, 
      long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   enq(si, idx);
}

void EConsumer::
fchdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
       int fd, long id, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
chmodat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
        int fd, long id, const char* fn, int mode, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].l = mode;
   si->curEv[idx]->fd = fd;
   enq(si, idx);
}

void EConsumer::
fchmod(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
       long id, int md, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].l = md;
   enq(si, idx);
}

void EConsumer::
chownat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, long id,
        const char* fn, long user, long grp, long flgs, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[0].u32[1].i = flgs;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].u32[0].i = (int)user;
   si->curEv[idx]->arg[2].u32[1].i = (int)grp;
   enq(si, idx);
};

void EConsumer::
fchown(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, long id,
       long user, long grp, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[1].i = 0;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].u32[0].i = (int)user;
   si->curEv[idx]->arg[2].u32[1].i = (int)grp;
   enq(si, idx);
}

void EConsumer::
ent_clone(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long flags) {
   int idx;
   SubjInfo *si = preOp(sc, sn, ts, tid, pid, idx);
   si->curEv[idx]->arg[0].l = flags;
   if (si->curEv[idx]->status == BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
close(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
      long unrep_rd, long unrep_wr, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].l = unrep_rd;   
   si->curEv[idx]->arg[1].l = unrep_wr;   
   enq(si, idx);
}

void EConsumer::
connect(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, long id,
        const uint8_t *saddr, unsigned salen, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = getEp(saddr, salen);
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
dup(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   enq(si, idx);
}

void EConsumer::
ent_execveat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
      long id, long flags, const char* fn, const char* const argv[], 
      const char* const envp[]) {
   int idx;
   SubjInfo *si = preOp(sc, sn, ts, tid, pid, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[0].u32[1].i = flags;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[1].ul = (uint64_t)copyargv(argv);
   si->curEv[idx]->arg[2].ul = (uint64_t)copyargv(envp);
   if (si->curEv[idx]->status >= BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
ent_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int code) {
   // Should handle exitgrp differently, but for now, we don't.
   int idx;
   SubjInfo *si = preOp(sc, sn, ts, tid, pid, idx);
   si->curEv[idx]->arg[0].l = code;

   // (a) Ensure that exit executes after all other operations, and
   // (b) Prevent future events from being enqueued ater the exit event.
   si->lastEvTime = max(si->lastEvTime, ts);
   si->curEv[idx]->ts = si->lastEvTime+2*CLK_ERR;
   uint64_t exitTime = si->lastEvTime;
   enq(si, idx); // There won't be an exit from this syscall, so enq now.
   si->exitTime = exitTime;
}

void EConsumer::
init_module(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
             const char* params, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(params);
   enq(si, idx);
}

void EConsumer::
finit_module(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
             int fd, long id, const char* params, int flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].i = flags;
   si->curEv[idx]->arg[0].u32[1].nm = create(params);
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
ent_kill(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int pid1, 
         int tid1, int sig) {
   int idx;
   SubjInfo *si = preOp(sc, sn, ts, tid, pid, idx);
   si->curEv[idx]->arg[0].l = pid1;
   si->curEv[idx]->arg[1].l = tid1;
   si->curEv[idx]->arg[2].l = sig;
   if (si->curEv[idx]->status >= BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
linkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd1, long id1,
  const char* fn1, int fd2, long id2, const char* fn2, long flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd1;
   si->curEv[idx]->id = id1;
   si->curEv[idx]->arg[0].u32[0].i = fd2;
   si->curEv[idx]->arg[0].u32[1].i = flags;
   si->curEv[idx]->arg[1].l = id2;
   si->curEv[idx]->arg[2].u32[0].nm = create(fn1);
   si->curEv[idx]->arg[2].u32[1].nm = create(fn2);
   enq(si, idx);
}

void EConsumer::
symlinkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
          const char* fn1, int fd, long id, const char* fn2, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].u32[0].nm = create(fn1);
   si->curEv[idx]->arg[2].u32[1].nm = create(fn2);
   enq(si, idx);
}

void EConsumer::
mkdirat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
        long id, const char* fn, int mode, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[0].u32[1].i = mode;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
mknodat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
        long id, const char* fn, int mode, int dev, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[0].u32[1].i = mode;
   si->curEv[idx]->id = id;
   si->curEv[idx]->arg[2].l = dev;
   enq(si, idx);
}

void EConsumer::
mmapex(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long id, 
             long addr, long len, int prot, int flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->id = id; // We get only id, not fd from mmap.
   si->curEv[idx]->arg[0].l = addr;
   si->curEv[idx]->arg[1].l = len;
   si->curEv[idx]->arg[2].u32[0].i = prot;
   si->curEv[idx]->arg[2].u32[1].i = flags;
   if (si->curEv[idx]->status == BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
mount(char sc, uint16_t sn, uint64_t ts, int tid, int pid, const char* src,
      const char *dst, const char* fstp, long flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(src);
   si->curEv[idx]->arg[0].u32[1].nm = create(dst);
   si->curEv[idx]->arg[1].u32[0].nm = create(fstp);
   si->curEv[idx]->arg[2].l = flags;
   enq(si, idx);
}

void EConsumer::
mprotect(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
             long addr, long len, int prot, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].l = addr;
   si->curEv[idx]->arg[1].l = len;
   si->curEv[idx]->arg[2].u32[0].i = prot;
   enq(si, idx);
}

void EConsumer::
openat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int at_fd, 
    const char* fn, int flags, int mode, int rv, long at_id, long ret_id) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, ret_id, idx);
   si->curEv[idx]->fd = at_fd;
   si->curEv[idx]->id = at_id;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[0].u32[1].i = flags;
   si->curEv[idx]->arg[1].u32[0].i = mode;
   si->curEv[idx]->arg[1].u32[1].i = rv;
   enq(si, idx);
}

void EConsumer::
pipe(char sc, uint16_t sn, uint64_t ts, int tid, int pid, bool is_sock, 
         int fd1, int fd2) {
   // This code is broken #ifndef USE_FD, but we ignore this because 
   // pipe_exit won't be called when IDs are used rather than FD.
   int idx;
   long rv = (((long)fd1)<<32)|fd2;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].l = is_sock;
   enq(si, idx);
}

void EConsumer::
ent_ptrace(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long request,
           int target_tid) {
   int idx;
   SubjInfo *si = preOp(sc, sn, ts, tid, pid, idx);
   si->curEv[idx]->arg[0].l = request;
   si->curEv[idx]->arg[1].l = target_tid;
   if (si->curEv[idx]->status >= BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
read(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
         long id, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
renameat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd1, long id1,
  const char* fn1, int fd2, long id2, const char* fn2, long flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd1;
   si->curEv[idx]->id = id1;
   si->curEv[idx]->arg[0].u32[0].i = fd2;
   si->curEv[idx]->arg[0].u32[1].i = flags;
   si->curEv[idx]->arg[1].l = id2;
   si->curEv[idx]->arg[2].u32[0].nm = create(fn1);
   si->curEv[idx]->arg[2].u32[1].nm = create(fn2);
   enq(si, idx);
}

void EConsumer::
rmdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, const char* fn, 
      long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = AT_FDCWD;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   enq(si, idx);
}

void EConsumer::
sendto(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
       const uint8_t *saddr, unsigned salen, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].u32[0].nm = getEp(saddr, salen);
   enq(si, idx);
}

void EConsumer::
setgid(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int rgid, 
           int egid, int sgid, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].l = rgid;
   si->curEv[idx]->arg[1].l = egid;
   si->curEv[idx]->arg[2].l = sgid;
   enq(si, idx);
}

void EConsumer::
setuid(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int ruid,
           int euid, int suid, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].l = ruid;
   si->curEv[idx]->arg[1].l = euid;
   si->curEv[idx]->arg[2].l = suid;
   enq(si, idx);
}

void EConsumer ::
socket(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int family,
            int type, int protocol, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].l = family;
   si->curEv[idx]->arg[1].l = type;
   si->curEv[idx]->arg[2].l = protocol;
   enq(si, idx);
}

void EConsumer::
vmsplice(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                   int fd, long id, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
truncate(char sc, uint16_t sn, uint64_t ts, int tid, int pid, const char* fn,
             long len, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->arg[1].l = len;
   enq(si, idx);
}

void EConsumer::
ftruncate(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
              long id, long len, int rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->arg[0].l = len;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

void EConsumer::
umount(char sc, uint16_t sn, uint64_t ts, int tid, int pid, const char* s,
               long flags, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->arg[0].u32[0].nm = create(s);
   si->curEv[idx]->arg[1].l = flags;
   enq(si, idx);
}

void EConsumer::
unlinkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int at_fd, 
         long at_id, const char* fn, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = at_fd;
   si->curEv[idx]->arg[0].u32[0].nm = create(fn);
   si->curEv[idx]->id = at_id;
   enq(si, idx);
}

void EConsumer::
write(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
          long id, long rv) {
   int idx;
   SubjInfo *si = prePostOp(sc, sn, ts, tid, pid, rv, idx);
   si->curEv[idx]->fd = fd;
   si->curEv[idx]->id = id;
   enq(si, idx);
}

#define inStartUp() (nsucc < 4000)

SubjInfo* EConsumer::
postOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long rv, int& idx) {
   idx = -1;
   reset_pbuf();
   update_nfailed(rv);
   SubjInfo* si = procMap.lookupData(tid);

   if (!si) {
      if (is_err(rv))
         return nullptr;
      else si = getSubj(tid, pid, ts);
   }
   // si is nonnull --- at a minimum, it points to a skeleton object

   vector<EventInfo*> expired;
   idx = best_matching_event(si->curEv, sc, sn, EXIT_SEEN, curtime_, expired);
   processExpired(expired);

   if (idx < 0) {
      // Matching syscall not found: means that we are seeing the exit before
      // the entry. Queue the exit on the subject's event queue. But if we are
      // in the startup phase, it is common to see tons of exits, and we don't
      // expect to see the corresponding entries since they happened before
      // eAudit started. So, we don't queue the eexits in that case.
      if (!inStartUp()) {
         si->curEv.push_back(newEvInfo());
         idx = si->curEv.size()-1;
         memset((void*)si->curEv[idx], 0, sizeof(EventInfo));
         si->curEv[idx]->ev_code = sc;
         si->curEv[idx]->status = EXIT_SEEN;
         si->curEv[idx]->seqnum = sn;
         si->curEv[idx]->ts = ts;
         si->curEv[idx]->arg[3].l = rv; 
         si->curEv[idx]->si = si;
      }
   }
   else {
      si->curEv[idx]->status = BOTH_SEEN;
      si->curEv[idx]->arg[3].l = rv;
   }

   return si;
}

static void 
set_ids(SubjInfo* si, int idx, int uid, int gid, long cgroup) {
   // From the code of eauditk.c and eParser.C, it looks like uid and gid
   // are always valid, so no need to check for invalid values.
   // if (uid != INVAL_UID && gid != INVAL_UID) {
      if (si->uid != uid && si->uid != INVAL_UID)
         errPrtf("tid %d: uid mismatch: stored=%d, actual=%d\n",
                  si->tid, si->uid, uid);
      if (si->gid != gid && si->gid != INVAL_UID)
         errPrtf("tid %d: gid mismatch: stored=%d, actual=%d\n",
                  si->tid, si->gid, gid);
      
      // @@@@ Should we wait till the execution of the syscall to update
      // uid/gid? We wait for execve, but do it immediately for fork/clone.
      if (si->curEv[idx]->ev_code == EXECVE_EX) {
         si->curEv[idx]->arg[3].u32[0].i = uid;
         si->curEv[idx]->arg[3].u32[1].i = gid;
      }
      else {
         si->uid = uid; 
         si->gid = gid;
      }
   //}
}

void EConsumer::
sc_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long rv) {
   int idx;
   SubjInfo* si = postOp(sc, sn, ts, tid, pid, rv, idx);
   if (si && idx >= 0 && si->curEv[idx]->status == BOTH_SEEN)
      enq(si, idx);
}

void EConsumer::
exec_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
            int parent_tid, int rv, int uid, int gid, long cgroup) {
   int idx;
   SubjInfo* si = postOp(sc, sn, ts, tid, pid, rv, idx);
   if (si && idx >= 0) {
      if (!is_err(rv))
         set_ids(si, idx, uid, gid, cgroup);
      if (si->curEv[idx]->status == BOTH_SEEN)
         enq(si, idx);
   }
}

void EConsumer::
clone_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
            int parent_tid, int rv, int uid, int gid, long cgroup) {

   // Fork/clones are special because:
   //
   //    (i) They create new subjects that will make syscalls, so we need 
   //        to create the corresponding SubjInfo to process their events.
   //
   //   (ii) Our event queues are set up to handle entry-exit paring, so are
   //        insufficient for the 3-way pairing in clone (1 entry + 2 exits).
   //
   //  (iii) Clone's return to child serves no purpose in the context of Host,
   //        which only needs the return value from the parent's return
   //
   // For these reasons, our usual strategy --- waiting for all events
   // associated with a syscall to arrive --- becomes much more complex and also
   // unnecessary. Instead, we need the following:
   //
   //   -- If the call fails, record the clone if parent SubjInfo is already
   //      present. Otherwise, ignore the clone. This case is simple because there
   //
   //   -- If the call succeeds, ensure that both the parent and child SubjInfo
   //      are created, and the clone is recorded. The cases to consider are: 
   //
   //      ++ Clone return to parent and we have seen the parent's entry. Match
   //         the entry event, queue for processing, and create child SubjInfo.
   //
   //      ++ Clone returns for child before parent: We recognize this case by
   //         the fact that we don't have child's SubjInfo. Our handling is to
   //         pretend that we saw the parent's clone return, given that we
   //         already have the child's tid.
   //
   //      ++ One of the two returns but we have not seen the entry. We pretend
   //         that we saw the entry, since we have pretty much all the info
   //         needed (but for clone flags, which is not critical). We may see
   //         the entry event later, but we will silently throw it away.
   //
   // So, we basically ignore clone entries, using them only in those instances
   // where they are successfully matched with a return. We need one of the two
   // clone returns in order to process it; we ignore the second one. 
   //

   reset_pbuf();
   int childtid = rv && !is_err(rv)? rv : tid;
   int parenttid = rv && !is_err(rv)? tid : parent_tid;
   SubjInfo* parent_si = procMap.lookupData(parenttid);
   SubjInfo* child_si = procMap.lookupData(childtid);
   if (child_si)
      child_si->definite_orphan = false;

   if (is_err(rv)) {
      nfailed++;
      update_fail_count((uint8_t)sc, rv);     // Unlike other syscalls, failed
                  // clones are not being queued, so update error counts here.
      if (!parent_si) return;
   }
   else {
      if (rv) {   // Clone returning to parent
         nsucc++; // Count only for parent (to avoid double counting)
         if (!parent_si) { // Create a minimal SubjInfo, so we can queue events
                           // etc. This minimal SubjInfo is different for
                           // threads because Host does not handle them yet.
            if (pid != tid) {
               SubjInfo* prsi = procMap.lookupData(pid);
               if (!prsi) {
                  errPrtf("Thread %d created before its thread group %d\n",
                          tid, pid);
                  prsi = getSubj(pid, pid, ts, uid, gid);
               }
               parent_si = new SubjInfo(tid, prsi, ts, false); // thread
               // procMap.insert(parent_si->tid, parent_si);
               procMap.update(parent_si->tid, parent_si);
            }
            else parent_si = getSubj(tid, pid, ts, uid, gid); // skeleton
         }
      }
      else { // Clone returning to child
        if (!parent_si)
          parent_si = getSubj(parent_tid, parent_tid, ts, uid, gid); // skeleton
      }
   }

   // parent_si is valid and non-null
   vector<EventInfo*> expired;
   int idx = best_matching_event(parent_si->curEv, sc, sn, EXIT_SEEN, 
                                 curtime_, expired);
   processExpired(expired);

   if (idx < 0 && !child_si) {
      // Clone entry hasn't been seen. Manufacture it. This OK since it shd be
      // rare, as logger SHOULD prioritize clone entry delivery. We'll miss
      // clone flag value but this shd be OK. 

      if (!is_err(rv) && !inStartUp()) { // Skip manufacture For unsuccessful
                                         // clones and in the starting phase.
        warnPrtf("Injecting entry for clone exit tid=%d pid=%d rv=%d ptid=%d\n",
                 tid, pid, rv, parent_tid);
        injected_clone_entries++;
        parent_si->curEv.push_back(newEvInfo());
        idx = parent_si->curEv.size()-1;
        parent_si->curEv[idx]->ev_code = sc;
        parent_si->curEv[idx]->si = parent_si;
        parent_si->curEv[idx]->arg[0].l = 0;
      }
   }

   if (idx >= 0) {
     parent_si->curEv[idx]->status = BOTH_SEEN;
     parent_si->curEv[idx]->seqnum = sn; // Use sn of exit event for ordering
     parent_si->curEv[idx]->arg[3].l = is_err(rv)? rv : childtid;  
     parent_si->curEv[idx]->ts = ts;
     set_ids(parent_si, idx, uid, gid, cgroup);
     if (!child_si && !is_err(rv)) {
       int flags = parent_si->curEv[idx]->arg[0].l;
       int childpid = rv? (flags & CLONE_THREAD? pid : childtid) : pid;
       child_si = new SubjInfo(SubjInstId(), childtid, childpid, parent_si->tid,
                               uid, gid, ts, false); // skeleton
       // procMap.insert(childtid, child_si);
       procMap.update(childtid, child_si);
     }
     enq(parent_si, idx);
   }
   return;
}

void EConsumer::
processExpired(vector<EventInfo*>& expired) {
   for (unsigned idx=0; idx < expired.size(); idx++) {
      auto cev = expired[idx];
      if (cev->ev_code != EXIT_EN && cev->ev_code != EXITGRP_EN) {
         if (cev->ev_code == CLONE_EX || cev->ev_code == FORK_EX) {
            if (nsucc > 50000) clones_wo_returns++;
            // Just discard them, as we have already processed them.
            cev->status = INJECTED_EXIT;
         }
                                     
         if (cev->status < INJECTED_EXIT) {
            expired_events++;
            warnPrtf("Expired: %s stat=%d tid=%d sn=%d ts=%ld\n",
                     scname[(int)cev->ev_code], (int)cev->status, cev->si->tid,
                     cev->seqnum, cev->ts);
         }

         cev->si->curEv.push_back(cev);
         enq(cev->si, cev->si->curEv.size()-1);
      }
   }
   expired.clear();
}

/*******************************************************************************
 * Once syscalls have been arranged in correct serial order, they are processed
 * by calling procSysCall function. It uses doXX functions to process each
 * syscall XX.
 ******************************************************************************/

extern bool prtInConsumer;
// static void prt_ts_and_pid(const EventInfo& ev);

void
EConsumer::procSyscall(EventInfo& ev) {
  static uint16_t lastsn;
  static const char* lastev;
  if (nsucc > 1000) {
    uint16_t sndiff = ev.seqnum - lastsn;
    if (sndiff > 100u) {
     noutofseq++;
     warnPrtf("Out of sequence processing of %s (tid=%d), lastev=%s lastsn=%hu,"
              " this sn=%hu\n", scname[(uint8_t)ev.ev_code],
              ev.si->tid, lastev, lastsn, ev.seqnum);
    }
    if (last_compl_ts_ > ev.ts + 1000) { // out-of-order my 1 microsec
       noutoforder++;
       // oohg.addPoint(last_compl_ts_ - ev.ts);
       if (last_compl_ts_ > ev.ts + 1000000) { // out-of-order my 1 millisec
          nmajoroo++;
          warnPrtf("Out of order processing of %s (tid=%d) by %g sec, "
                   "already processed t=%ld\n", scname[(uint8_t)ev.ev_code],
                   ev.si->tid, (last_compl_ts_-ev.ts)/1e9, last_compl_ts_);
       }
    }
  }
  last_compl_ts_ = ev.ts;
  lastsn = ev.seqnum;
  lastev = scname[(uint8_t)ev.ev_code];

  if (ev.si->id == nullsiid.id()) {
    if (!ev.si->definite_orphan && !inStartUp())
     warnPrtf("Converting skeleton (pid=%d, tid=%d) to preexisting after %gs\n",
              ev.si->pid, ev.si->tid, (maxts_-ev.ts)/1e9);
    createExistingSubj(ev.si->tid, ev.si->pid, ev.ts, procopt);
  }
  assert_abort(ev.si->id != nullsiid.id());

  succ_count[(uint8_t)ev.ev_code]++;
  long ret = ev.arg[3].l;
  if (!is_err(ret)) {
     ev.si->seqnum = ev.seqnum;
     ev.si->syscall = scname[(unsigned)ev.ev_code];

     switch (ev.ev_code) {
     case ACCEPT_EX:   doaccept(ev); break;
     case BIND_EX:     dobind(ev); break;
     case CHDIR_EX:    dochdir(ev); break;
     case FCHDIR_EX:   dofchdir(ev); break;
     case CHMOD_EX:    dochmod(ev); break;
     case FCHMOD_EX:   dofchmod(ev); break;
     case CHOWN_EX:    dochown(ev); break;
     case FCHOWN_EX:   dofchown(ev); break;
     case CLONE_EX:    doclone(ev); break;
     case CLOSE_EN:    doclose(ev); break;
     case CONNECT_EX:  doconnect(ev); break;
     case DUP_EX:      dodup(ev); break;
     case EXECVE_EX:   doexecve(ev); break;
     case EXIT_EN:     doexit(ev); break;
     case EXITGRP_EN:  doexitgrp(ev); break;
     case FORK_EX:     doclone(ev); break;
     case GETPEER_EX:  dogetpeer(ev); break;
     case INITMOD_EX:  doinitmod(ev); break;
     case FINITMOD_EX: dofinitmod(ev); break;
     case KILL_EX:     dokill(ev); break;
     case LINK_EX:     dolink(ev); break;
     case SYMLINK_EX:  dosymlink(ev); break;
     case MKDIR_EX:    domkdir(ev); break;
     case MKNOD_EX:    domknod(ev); break;
     case MMAP_EX:     dommap(ev); break;
     case MOUNT_EX:    domount(ev); break;
     case MPROTECT_EX: domprotect(ev); break;
     case OPEN_EX:     doopen(ev); break;
     case PIPE_EX:     dopipeopen(ev); break;
     case PTRACE_EX:   doptrace(ev); break;
     case READ_EX:
     case PREAD_EX:    doreadwr(ev, true); break;
     case RECVFROM_EX: dorecvfrom(ev); break;
     case RENAME_EX:   dorename(ev); break;
     case RMDIR_EX:    dormdir(ev); break;
     case SENDTO_EX:   dosendto(ev); break;
     case SETGID_EX:   dosetgid(ev); break;
     case SETUID_EX:   dosetuid(ev); break;
     case VMSPLICE_EX: dovmsplice(ev); break;
     case TRUNC_EX:    dotruncate(ev); break;
     case FTRUNC_EX:   doftruncate(ev); break;
     case UNLINK_EX:   dounlink(ev); break;
     case UMOUNT_EX:   doumount(ev); break;
     case WRITE_EX:
     case PWRITE_EX:   doreadwr(ev, false); break;
     default: break;
        errPrtf("Unknown syscall %s\n", scname[(uint8_t)ev.ev_code]);
        break;
     }
  }
  else update_fail_count((uint8_t)ev.ev_code, ret);
  free(ev);
}

// Process operations

void EConsumer::
doclone(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long flags = ev.arg[0].l;
   SubjInfo *chsi;
   SubjInstId chsid;
   int chtid = (int)ev.arg[3].l;

   if (chtid == 0) {
      nchildret++; // We should not reach here
      return;
   }

   // parent's return. Child's return of clone is not to be delivered to clients
   if (flags & CLONE_THREAD)
      nthreads++;
   else nprocs++;

   SubjInfo* temp_chsi = procMap.lookupData(chtid);
   if (temp_chsi) { // Replace the auto-created SubjInfo for child with a 
      assert_abort(temp_chsi->tid == chtid); // clone of the parent process.
      int uid = temp_chsi->uid;   // We overwrite the minimal SubjInfo with a
      int gid = temp_chsi->gid;   // copy of parent. Some field that may have
      int pid = temp_chsi->pid;   // been modified in the minimal SubjInfo are
      auto ev = temp_chsi->curEv; // saved and then propagated to
      chsi = new (temp_chsi) SubjInfo(*si);   // this clone. With this
      chsi->uid = uid;            // clone, the minimal auto-created subject is
      chsi->gid = gid;            // gone, so replaced by an explicitly
      chsi->pid = pid;            // created one, i.e., reset the flag and
      chsi->curEv = ev;           // adjust the autocreated count. 
   }
   else {
      chsi = new SubjInfo(*si);
      chsi->curEv.clear();
      // procMap.insert(chtid, chsi);
      procMap.update(chtid, chsi);
   }
   chsi->tid = chtid;
   chsi->ptid = si->tid;
   chsi->lastEvTime = max(ev.ts, chsi->lastEvTime);
   if (!erecorder_)
      chsi->id = nsubj;
   else chsi->id = erecorder_->clone(si, temp_chsi, flags, ev.ts);

   for (auto cli: clients_)
      if (cli != erecorder_)
         cli->clone(si, temp_chsi, flags, ev.ts);
}

void EConsumer::
doexecve(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int at_fd = ev.fd;
   long at_id = ev.id;
   StrId nm = ev.arg[0].u32[0].nm;
   int flags = ev.arg[0].u32[1].i;
   auto argv = (const StrId*)ev.arg[1].ul;
   auto envp = (const StrId*)ev.arg[2].ul;
   int uid = ev.arg[3].u32[0].i;
   int gid = ev.arg[3].u32[1].i;

   auto obj = nm2ObjAt(si, at_fd, at_id, nm, ev.ts, NmOpt(OLD,FILET,fileopt));
   si->args = argv;
   si->envs = envp;
   si->setexe(obj);

   for (auto cli: clients_) {
      cli->execve(si, obj, flags, ev.ts);
      if (si->uid != uid)
         cli->setuid(si, uid, INVAL_UID, INVAL_UID, 0, ev.ts);
      if (si->gid != gid)
         cli->setgid(si, gid, INVAL_UID, INVAL_UID, 0, ev.ts);
   }
}

void EConsumer::
doexit(EventInfo& ev) {
   SubjInfo *si = ev.si;
   unsigned still_events = 0;
   long code = ev.arg[0].l;

   processExpired(si->curEv);
   for (auto cli: clients_)
      cli->exit(si, code, ev.ts);

   procMap.remove(si->tid);
   if (!still_events)
      delete si;
}

void EConsumer::
doexitgrp(EventInfo& ev) {
// @@@@ Needs information about tids in a process so that they can all exit. 
// @@@@ With the current implementation, all threads except one will live 
// @@@@ forever in Host. Until Host is cleaned up, it is not easy to fix this.

   doexit(ev);
}

void EConsumer::
dokill(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int pid = (int)ev.arg[0].l;
   int tid = (int)ev.arg[1].l;
   int sig = (int)ev.arg[2].l;
   long rv = ev.arg[3].l;

   auto chsi = getSubj(tid, pid, ev.ts);
   for (auto cli: clients_)
      cli->kill(si, chsi, sig, rv, ev.ts);
}

void EConsumer::
doptrace(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long request = ev.arg[0].l;
   long target_tid = ev.arg[1].l;
   long rv = ev.arg[3].l;
   
   SubjInfo *tsi = NULL;
   if (request != PTRACE_TRACEME) { // We are not reporting ptrace_traceme
      tsi = getSubj(target_tid, target_tid, ev.ts);
      if (tsi->id == nullsiid_i)
         tsi = createExistingSubj(tsi->tid, tsi->pid, ev.ts, procopt);
      for (auto cli: clients_)
         cli->ptrace(si, tsi, request, rv, ev.ts);
   }
}

void EConsumer::
dosetuid(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long ruid = ev.arg[0].l;
   long euid = ev.arg[1].l;
   long suid = ev.arg[2].l;
   long ret = ev.arg[3].l;

   for (auto cli: clients_)
      cli->setuid(si, euid, ruid, suid, ret, ev.ts);
   si->uid = euid;
}

void EConsumer::
dosetgid(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long rgid = ev.arg[0].l;
   long egid = ev.arg[1].l;
   long sgid = ev.arg[2].l;
   long ret = ev.arg[3].l;

   for (auto cli: clients_)
      cli->setgid(si, egid, rgid, sgid, ret, ev.ts);
   si->gid = egid;
}

// Network operations and IPC

// %%%% For syscalls that change something, report Subject and Object state
// %%%% before the operation. This way, clients have access to both the
// %%%% before and after state. (For creation operations and operations that
// %%%% set attributes that aren't meaningful to change, we return 
// %%%% post-state.)

void EConsumer::
doaccept(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = ev.id;
   StrId remEp = ev.arg[0].u32[0].nm;
   long rv = ev.arg[3].l;

   Obj* oi = createSocket(si, id, remEp, ev.ts);
   for (auto cli: clients_)
      cli->accept(si, oi, fd, rv, ev.ts);
}

void EConsumer::
dobind(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = 0;
   StrId ep = ev.arg[0].u32[0].nm;
   long rv = ev.arg[3].l;

   Obj* oi = createSocket(si, id, ep, ev.ts);
   for (auto cli: clients_)
      cli->bind(si, oi, fd, rv, ev.ts);
}

void EConsumer::
doconnect(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = ev.id;
   StrId remEp = ev.arg[0].u32[0].nm;
   long rv = ev.arg[3].l;

   Obj* oi = createSocket(si, id, remEp, ev.ts);
   for (auto cli: clients_)
      cli->connect(si, oi, fd, rv, ev.ts);
}

void EConsumer::
dogetpeer(EventInfo& ev) {
   SubjInfo *si = ev.si;
   // int fd = ev.fd;  
   StrId remEp = ev.arg[0].u32[0].nm;
   long id = ev.id;
   // long rv = ev.arg[3].l;

   createSocket(si, id, remEp, ev.ts);
   // All we want to do here is to update the id2nm and nm2oi maps. The
   // syscall itself is not of much interest, so we don't bother delivering it.
}

void EConsumer::
dosendto(EventInfo& ev) {
   SubjInfo *si = ev.si;
   nreadwr++;
   int fd = ev.fd;
   StrId remEp = ev.arg[0].u32[0].nm;
   long id = ev.id; // @@@@ Wrong?? No id is assigned in sendto
   long rv = ev.arg[3].l;

   Obj* oi = createSocket(si, id, remEp, ev.ts);
   for (auto cli: clients_)
      cli->sendto(si, oi, fd, rv, ev.ts);
}

void EConsumer::
dorecvfrom(EventInfo& ev) {
   SubjInfo *si = ev.si;
   nreadwr++;
   int fd = ev.fd;
   StrId remEp = ev.arg[0].u32[0].nm;
   long id = ev.id;
   long rv = ev.arg[3].l;

   Obj* oi = createSocket(si, id, remEp, ev.ts);
   for (auto cli: clients_)
      cli->recvfrom(si, oi, fd, rv, ev.ts);
}

void EConsumer::
dosocket(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int family = ev.arg[0].l;
   int type = ev.arg[1].l;
   int protocol = ev.arg[2].l;
   long rv = ev.arg[3].l;

   for (auto cli: clients_)
      cli->socket(si, family, type, protocol, rv, ev.ts);
}

void EConsumer::
dopipeopen(EventInfo& ev) {
  SubjInfo *si = ev.si;
  int fd0 = ev.arg[3].l>>32;
  int fd1 = ev.arg[3].l;
  bool is_sock = (bool)ev.arg[0].l;

  for (auto cli: clients_)
     if (is_sock)
        cli->sockpair(si, fd0, fd1, ev.ts);
     else cli->pipe(si, fd0, fd1, ev.ts);
}

void EConsumer::
dodup(EventInfo& ev) {
  SubjInfo *si = ev.si;
  int fd1 = ev.fd;
  int fd2 = (int)ev.arg[3].l;

   for (auto cli: clients_)
      cli->dup(si, fd1, fd2, ev.ts);
}

// Open, close, read, write, etc.

void EConsumer::
doopen(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long at_fd = ev.fd;
   long at_id = ev.id;
   StrId nm = ev.arg[0].u32[0].nm;
   int flags = (int)ev.arg[0].u32[1].i;
   int mode = (int)ev.arg[1].u32[0].i;
   int fd = (int)ev.arg[1].u32[1].i;
   long ret_id = ev.arg[3].l;

   CreationFlag create_op = OLD;
   if (flags & O_CREAT)
         create_op = (flags & O_EXCL)? NEW : MAYBE_NEW;

   Obj* oi = nm2ObjAt(si, at_fd, at_id, nm, ev.ts, 
                      NmOpt(create_op, FILET, fileopt), ret_id); 
   for (auto cli: clients_)
      cli->open(si, oi, flags, mode, fd, ev.ts);
}

void EConsumer::
doclose(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   // long unrep_rd = ev.arg[0].l;
   // long unrep_wr = ev.arg[1].l;

   // It is unlikely that close operations will be reported, so avoid any fancy
   // state reconstruction and just send the call and its params.
   for (auto cli: clients_)
      cli->close(si, fd, ev.ts);
}

void EConsumer::
dotruncate(EventInfo& ev) {
   SubjInfo *si = ev.si;
   StrId nm = ev.arg[0].u32[0].nm;
   long len = ev.arg[1].l;
   long rv = ev.arg[3].l;

   auto obj = nm2ObjAt(si, AT_FDCWD, 0, nm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->truncate(si, obj, len, rv, ev.ts, -1);
}

void EConsumer::
doftruncate(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long len = ev.arg[0].l;
   long id = ev.id;
   long rv = ev.arg[3].l;

   Obj* obj = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->truncate(si, obj, len, rv, ev.ts, fd);
}

void EConsumer::
domkdir(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   StrId nm = ev.arg[0].u32[0].nm;
   int mode = ev.arg[0].u32[1].i;
   long id = ev.id;
   long rv = ev.arg[3].l;

   StrId fnm = fullpath(si, fd, id, nm, ev.ts, NmOpt(OLD, FILET, fileopt));

   for (auto cli: clients_)
      cli->mkdir(si, fnm, mode, rv, ev.ts);
   // Should we create the object? On the one hand, we have some info: the 
   // dir has been created with certain mode etc. But we don't have the id.
}

void EConsumer::
domknod(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   StrId nm = ev.arg[0].u32[0].nm;
   int mode = ev.arg[0].u32[1].i;
   long id = ev.id;
   int dev = (int)ev.arg[2].l;
   long rv = ev.arg[3].l;

   StrId fnm = fullpath(si, fd, id, nm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->mknod(si, fnm, mode, dev, rv, ev.ts);
   // Should we create the object? On the one hand, we have some info: the 
   // node has been created with certain mode etc. But we don't have the id.
}

void EConsumer::
doreadwr(EventInfo& ev, bool rd) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = ev.id;
   long rv = ev.arg[3].l;

   nreadwr++;
   Obj* obj = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      if (rd)
         cli->read(si, obj, fd, rv, ev.ts);
      else cli->write(si, obj, fd, rv, ev.ts);
}

void EConsumer::
dovmsplice(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = ev.id;
   long rv = ev.arg[3].l;

   Obj* obj = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->vmsplice(si, obj, fd, rv, ev.ts);
}

void EConsumer::
dommap(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long id = ev.id;
   long addr = ev.arg[0].l; // mmap returns address.
   long len = ev.arg[1].l;
   int prot = ev.arg[2].u32[0].i;
   int flags = ev.arg[2].u32[1].i;
   long rv = ev.arg[3].l;

   auto obj = resolveId(si, 0, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->mmap(si, obj, addr, len, prot, flags, rv, ev.ts);
}

void EConsumer::
domprotect(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long addr = ev.arg[0].l;
   long len = ev.arg[1].l;
   int prot = ev.arg[2].u32[0].i;
   long rv = ev.arg[3].l;

   for (auto cli: clients_)
      cli->mprotect(si, addr, len, prot, rv, ev.ts);
}

// link, rename, rmdir, etc.

void EConsumer::
dolink(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd1 = ev.fd;
   int fd2 = ev.arg[0].u32[0].i;
   int flags = ev.arg[0].u32[1].i;
   long id1 = ev.id;
   long id2 = ev.arg[1].l;
   StrId nm1 = ev.arg[2].u32[0].nm;
   StrId nm2 = ev.arg[2].u32[1].nm;
   long rv = ev.arg[3].l;

   Obj* oldo = nm2ObjAt(si, fd1, id1, nm1, ev.ts, NmOpt(OLD, FILET, fileopt));
   StrId fnm = fullpath(si, fd2, id2, nm2, ev.ts, NmOpt(OLD, FILET, fileopt));

   for (auto cli: clients_)
      cli->link(si, oldo, fnm, flags, rv, ev.ts);
   // Should we create the object? On the one hand, we have some info: The id
   // of old object and the rest of its info can be transferred to the new obj.
   // But we don't know if the id is correct, as we are just relying on 
   // cached info.
}

void EConsumer::
dosymlink(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd2 = ev.fd;
   long id2 = ev.id;
   StrId oldnm = ev.arg[2].u32[0].nm;
   StrId newnm = ev.arg[2].u32[1].nm;
   long rv = ev.arg[3].l;

   Obj* oldo = nm2ObjAt(si, AT_FDCWD, 0, oldnm, ev.ts, 
                        NmOpt(OLD, FILET, fileopt));
   StrId fnm = fullpath(si, fd2, id2, newnm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->symlink(si, oldo, fnm, rv, ev.ts);
   // Should we create the object? On the one hand, we have some info: The id
   // of old object and the rest of its info can be transferred to the new obj.
   // But we don't know if the id is correct, as we are just relying on 
   // cached info. Plus, this is a symlink, and we don't represent that.
}

void EConsumer::
dorename(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd1 = ev.fd;
   long id1 = ev.id;
   int fd2 = ev.arg[0].u32[0].i;
   long id2 = ev.arg[1].l;
   int flags = ev.arg[0].u32[1].i;
   StrId fn1 = ev.arg[2].u32[0].nm;
   StrId fn2 = ev.arg[2].u32[1].nm;
   long rv = ev.arg[3].l;

   Obj* oldobj = nm2ObjAt(si, fd1, id1, fn1, ev.ts, 
                                  NmOpt(OLD, FILET, CREATE_BEST_EFFORT));
   StrId fnm = fullpath(si, fd2, id2, fn2, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->rename(si, oldobj, fnm, flags, rv, ev.ts);
   // Should we create the object? On the one hand, we have some info: The id
   // of old object and the rest of its info can be transferred to the new obj.
   // But we don't know if the id is correct, as we are relying on cached info.
}

void EConsumer::
dounlink(EventInfo& ev, bool is_rmdir) {
   SubjInfo *si = ev.si;
   long at_fd = ev.fd;
   StrId nm = ev.arg[0].u32[0].nm;
   long at_id = ev.id;
   long rv = ev.arg[3].l;

   Obj* oldo = nm2ObjAt(si, at_fd, at_id, nm, ev.ts, 
                                NmOpt(OLD, FILET, CREATE_BEST_EFFORT));
   for (auto cli: clients_)
      cli->unlink(si, oldo, rv, ev.ts);
}

void EConsumer::
dormdir(EventInfo& ev) {
   dounlink(ev, true);
}

// chdir, chmod, etc.

void EConsumer::
dochdir(EventInfo& ev) {
  SubjInfo *si = ev.si;
  StrId nm = ev.arg[0].u32[0].nm;
  long rv = ev.arg[3].l;

  Obj* o = nm2ObjAt(si, AT_FDCWD, nullid, nm, ev.ts, 
                    NmOpt(OLD, FILET, fileopt));
  for (auto cli: clients_)
     cli->chdir(si, o, rv, ev.ts, -1);
  si->setcwd(o);
}

void EConsumer::
dofchdir(EventInfo& ev) {
  SubjInfo *si = ev.si;
  int fd = ev.fd;
  long id = ev.id;
  long rv = ev.arg[3].l;

  Obj* oi = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
  for (auto cli: clients_)
     cli->chdir(si, oi, rv, ev.ts, fd);
  si->setcwd(oi);
}

void EConsumer::
dochmod(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int at_fd = ev.fd;
   long at_id = ev.id;
   StrId nm = ev.arg[0].u32[0].nm;
   int mode = (int)ev.arg[2].l;
   long rv = ev.arg[3].l;

   Obj* oi = nm2ObjAt(si, at_fd, at_id, nm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->chmod(si, oi, mode, rv, ev.ts, -1);
   oi->mode = mode;
}

void EConsumer::
dofchmod(EventInfo& ev) {
   SubjInfo *si = ev.si;
   long id = ev.id;
   int mode = (int)ev.arg[2].l;
   int fd = ev.fd;
   long rv = ev.arg[3].l;

   Obj* oi = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->chmod(si, oi, mode, rv, ev.ts, fd);
   oi->mode = mode;
}

void EConsumer::
dochown(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int at_fd = ev.fd;
   StrId nm = ev.arg[0].u32[0].nm;
   int flags = ev.arg[0].u32[1].i;
   long at_id = ev.id;
   int user = (int)ev.arg[2].u32[0].i;
   int grp  = (int)ev.arg[2].u32[1].i;
   long rv = ev.arg[3].l;

   Obj* oi = nm2ObjAt(si, at_fd, at_id, nm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->chown(si, oi, user, grp, flags, rv, ev.ts, -1);
   oi->uid = user;
   oi->gid = grp;
}

void EConsumer::
dofchown(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;
   long id = ev.id;
   int user = ev.arg[2].u32[0].i;
   int grp  = ev.arg[2].u32[1].i;
   long rv = ev.arg[3].l;

   Obj* oi = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->chown(si, oi, user, grp, 0, rv, ev.ts, fd);
   oi->uid = user;
   oi->gid = grp;
}

// Other administrative operations

void EConsumer::
doinitmod(EventInfo& ev) {
   SubjInfo *si = ev.si;
   StrId params = ev.arg[0].u32[0].nm;
   long rv = ev.arg[3].l;

   for (auto cli: clients_)
      cli->init_module(si, params, rv, ev.ts);
}

void EConsumer::
dofinitmod(EventInfo& ev) {
   SubjInfo *si = ev.si;
   int fd = ev.fd;  
   int id = ev.id;  
   int flags = ev.arg[0].u32[0].i;
   StrId params = ev.arg[0].u32[1].nm;
   long rv = ev.arg[3].l;

   Obj* oi = resolveId(si, fd, id, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->finit_module(si, oi, fd, params, flags, rv, ev.ts);
}

void EConsumer::
domount(EventInfo& ev) {
   SubjInfo *si = ev.si;
   StrId devName = ev.arg[0].u32[0].nm;
   StrId dirName = ev.arg[0].u32[1].nm;
   StrId fsType = ev.arg[1].u32[0].nm;
   long flags = ev.arg[2].l;
   long rv = ev.arg[3].l;

   StrId devnm = fullpath(si, AT_FDCWD, 0, devName, ev.ts, NmOpt(OLD, FILET, fileopt));
   StrId dirnm = fullpath(si, AT_FDCWD, 0, dirName, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->mount(si, devnm, dirnm, fsType, flags, rv, ev.ts);
   // This is such a rare case that the fact that we don't create an
   // object shouldn't affect much.
}

void EConsumer::
doumount(EventInfo& ev) {
   SubjInfo *si = ev.si;
   StrId nm = ev.arg[0].u32[0].nm;
   long flags = ev.arg[1].l;
   long rv = ev.arg[3].l;

   StrId fnm = fullpath(si, AT_FDCWD, 0, nm, ev.ts, NmOpt(OLD, FILET, fileopt));
   for (auto cli: clients_)
      cli->umount(si, fnm, flags, rv, ev.ts);
   // This is such a rare case that the fact that we don't create an
   // object shouldn't affect much.
}

void EConsumer::
finalize() {
   dqAndDo(true);
}

void EConsumer::
free(EventInfo& ev) {
   freeEv_.push(&ev);
}

EventInfo* EConsumer::
newEvInfo() {
   if (freeEv_.empty()) 
      return new EventInfo();
   else {
      EventInfo* rv = freeEv_.top();
      freeEv_.pop();
      return rv;
   }
}

unsigned qsize_;
#define USE_SEQNUM
#ifdef USE_SEQNUM

/*******************************************************************************
 * Sequence-number based queueing. Later events should have higher sequence
 * numbers than earlier ones, but the sequence numbers need not be unique.
 * Because of this possibility of non-uniqueness, we cannot directly use them as
 * the index in a queue. Instead, we multiply them by a factor --- currently, 2.
 * (The factor can be decreased further if the sequence numbers are perfect.
 * Conversely, the factor should be increased if the sequence number is less
 * reliable (and more "clumped"). The logic is not particularly complicated by
 * this multiplication. In addition, using a factor of 9 vs 2 does not seem to
 * make a difference in runtime. So, for now, we have stuck with the factor 2.)
 ******************************************************************************/

#define QFAC 2
// QFAC=1 requires perfect sequence numbers (no duplication, even as a result of
// delayed events). A factor such as 2 will tolerate errors.
#define QSIZE QFAC*(1<<16)
EventInfo* q_[QSIZE];
unsigned qbeg_;
uint64_t first_ts, latest_queued_ts;

// If we are querying the OS for missing info, it is important to dequeue and
// "execute" events in a timely fashion: we query the OS when executing an
// event, as we know by then if we already have the info (e.g., inherited from
// parent process). Queuing too long means that the state we retrieve can
// reflect system long past the time of event execution. So we dequeue when (a)
// queue is more than half-full, OR (b) the first event in the queue is more
// than 2 seconds old. 
//
// For time-based things to work reliably, we should have current real time
// reported frequently into EConsumer. Inferring ts from events proved difficult
// to get right. (Our notion of latest time can get thrown off by a timestamp
// that is off --- and we still don't have enough confidence in individual
// timestamps.)

static constexpr uint64_t toolong_in_q = 2*1000*1000*1000;
static bool ready_to_dq(uint64_t cur_ts) {
   return ((qsize_ > 32000) || (cur_ts > first_ts + toolong_in_q));
}

bool EConsumer::
do_enq(EventInfo& ev) {
   unsigned islot = QFAC*ev.seqnum;
   if (!first_ts) 
      first_ts = ev.ts;

   unsigned qpos = islot;
   if (qpos < qbeg_)
      qpos += QFAC*(1<<16);
   qpos -= qbeg_;

   // To be considered late, this event's position shd be far greater than qsize
   if (qpos > (16000 + qsize_)*QFAC && nsucc > 5) {
      tooLateEvent++;
      errPrtf("Too late event %s (delay=%gs), sn=%u (qbeg=%u, qlen=%u): processed "
              "immediately\n", scname[(int)ev.ev_code], 
              latest_queued_ts/1e9-ev.ts/1e9, islot, qbeg_, qsize_);
      if (ev.ev_code != EXIT_EN && ev.ev_code != EXITGRP_EN) {
         procSyscall(ev);
         return false;
      }
   }

   latest_queued_ts = max(latest_queued_ts, ev.ts);

/* 
   // Under no circumstances do we want to execute exits early. (But delaying
   // them to execute at a different sequence number leads to conflicts.) For
   // other events, we check if the the time is already past. It is past if
   // the event's execution time is long past (~64ms) in the past, or its 
   // in the recent past but its sequence number puts it more than 10K slots
   // ahead of the queue beginning.
   if (ev.ev_code != EXIT_EN && ev.ev_code != EXITGRP_EN && 
       ((ev.ts + (1<<26) <= last_compl_ts_) ||
        ((ev.ts + CLK_ERR <= last_compl_ts_) && (islot - qbeg_ > 10000)))) {
      tooLateEvent++;
      procSyscall(ev);
      return false;
   }

   // If ev's timestamp is far into the future as compared to the latest
   // event in the queue, complain that ev has been reported too early;
   // or equivalently (from our vantage point), the clock has jumped ahead. 
   if (ev.ts > latest_queued_ts) {
      if (ev.ts - latest_queued_ts > (1<<24) && nsucc > 5) {
         if (ev.ts - latest_queued_ts > (1<<30))
         // 16ms seems long enough that there should have been some event. It is
         // probably the smallest amount of time in which 64K events can occur, 
         // causing sequence numbers to be incorrect (due to wrap-around.) But
         // 16ms lag seems so common that we just warn, and error only at 1s
            errPrtf("Timestamp %lu, seq# %hu: jump ahead by %g s\n", 
                    ev.ts, ev.seqnum, (ev.ts-latest_queued_ts)/1e9);
         else warnPrtf("Timestamp %lu, seq# %hu: jump ahead by %g s\n", 
                    ev.ts, ev.seqnum, (ev.ts-latest_queued_ts)/1e9);

         tooEarlyEvent++;
      }
      latest_queued_ts = ev.ts;
   }
*/

   // Now, look for an empty slot to queue ev. Start with initial slot derived
   // from sequence #,iterate through the next several (32) numbers.

   unsigned slot, j;
   unsigned alternate_slot = QSIZE;
   for (j=0; j < 32; j++) {
      slot = islot+j;
      if (slot >= QSIZE)
         slot -= QSIZE;

      // If the chosen slot is occupied by a very old event, dislodge that
      // event by processing it. Then use the slot for ev. If that event is
      // not so old, then continue the search. 

      if (q_[slot]) {
         EventInfo& oe = *q_[slot];
         if (oe.ev_code == EXIT_EN || oe.ev_code == EXITGRP_EN)
            continue;
         if (oe.ts < ev.ts - (1<<20)) {
            // Consider it SN's use as part of the previous generation
            oldEvTimeDiff.addPoint(ev.ts - oe.ts);
            procSyscall(oe);
            q_[slot] = &ev;
            searchlen.addPoint((slot-islot)&((1<<10)-1));
            return true;
         }
         else if (alternate_slot == QSIZE)
            alternate_slot = slot;
         // alternate slot will be used if this loop fails to find an empty slot
      }
      else break;
   }

   if (j > 0) // if islot is occupied, then we consider it a collision. (We are
      ncollisions++; // not counting how many other slots we had to look at.)
   if (q_[slot]) {
      nbadcollisions++; // bad collision: failed to find a slot after 32 tries
      slot = alternate_slot;
      if (slot == QSIZE) {
         errPrtf("Seq# %hu conflict: new ev=%s@%lu, dropping\n", slot,
              scname[(uint8_t)ev.ev_code], ev.ts);
         return false;
      }

      // On bad collisions, we process one of the colliding events right away
      // so that the other event can occupy its slot.
      EventInfo& oe = *q_[slot];
      errPrtf("Seq# %hu conflict: new ev=%s@%lu, exist. ev=%s@%lu: ", islot,
              scname[(uint8_t)ev.ev_code], ev.ts,
              scname[(uint8_t)oe.ev_code], oe.ts);
      if (oe.ts < ev.ts) {
         errPrtf("executing existing event now\n");
         procSyscall(oe);
         q_[slot] = &ev;
         return true;
      }
      else {
         errPrtf("executing new event early\n");
         procSyscall(ev);
         return false;
      }
   }

   searchlen.addPoint((slot-islot) & ((1<<10)-1));
   q_[slot] = &ev;
   qsize_++;
   return true;
}

EventInfo* EConsumer::
dq() { 
   EventInfo *rv;
   unsigned cur = qbeg_;

   // The above enqueuing algorithm means that many slots in the queue will be
   // unoccupied, i.e., contain a zero value. So, we loop through such slots,
   while (!(rv = q_[cur]))
      if (++cur == QSIZE)
         cur = 0;

   // dqlen.addPoint((uint16_t)(cur - qbeg_));

   qbeg_ = cur;
   q_[qbeg_] = 0;
   if (++qbeg_ == QSIZE)
      qbeg_ = 0;
   qsize_--;

   if (rv)
      first_ts = rv->ts;
   return rv;
};

#else 

/*******************************************************************************
 * Timestamp-based queuing and serialization. We use a vector of vectors for
 * queuing the events. The outer vector consists of buckets, each maintained as
 * (an inner) vector. To determine the bucket for an event, we simply shift out
 * the rightmost EVQ_BUCKETS bits of its timestamp. Each inner vector
 * consists of events that fall in the same bucket of timestamps.
 *
 * The number and sizes of buckets were tuned to reduce runtime as well as
 * serialization errors. In particular, (1 << (EVQ_BKTS+EVQ_BKT_SHIFT))
 * represents the duration (in nanoseconds) for which events will be queued.
 * There is no overhead for finding the bucket from an event's timestamp, but
 * the events within buckets need to be in sorted order. We find that there is
 * no gain in using a priority queue for this purpose, and that it is much
 * faster to simply sort each bucket before we process its events. (This
 * approach is also simpler.)
 *
 * Note that the bucket scheme incurs some ordering errors for events at the end
 * of buckets. Specifically, due to lack of synchronization of clocks across
 * cores, a later event may have a time stamp before an earlier event. CLK_ERR
 * captures the max such error we have encountered in our (far from exhaustive)
 * experiments. 
 ******************************************************************************/

#define EVQ_BKTS    (1<<16)
#define EVQ_BKT_SHIFT 14
uint64_t maxwait_ = EVQ_BKTS * (1ul << EVQ_BKT_SHIFT);

vector<EventInfo*> q_[EVQ_BKTS];
// For efficiency, the outer queue is implemented as a circular queue. Its first
// bucket, i.e., the bucket with earliest timestamps in the queue, is given by
// qbeg_. qbeg_next_ represents the first unprocessed event in this first bucket.

unsigned qbeg_, qbeg_next_;

// qbeg_ts1_ is derived from the timstamp of the first event. It represents the
// smallest possible timestamp, and its value is subtracted from a timestamp
// before calculating its bucket. The use of qbeg_ts1_ seems to improve
// understandability of code but is not fundamantal. OTOH, qbeg_ts plays a key
// role: it is the timestamp of the earliest event in the queue (i.e., the
// earliest event in the earliest (i.e., very first) bucket.

uint64_t qbeg_ts_, qbeg_ts1_;

static int get_bucket(EventInfo& ev) {
   if (ev.ts + CLK_ERR <= last_compl_ts_ && ev.ev_code != EXIT_EN && 
       ev.ev_code != EXITGRP_EN) 
      // This means that an earlier event has already been executed: this event
      // is already too late and will be executed out of order. Avoid further
      // delay by processing it immediately without queueing. As usual, exit
      // events get special treatment to ensure that a subject is still around
      // when one of its events arrives.
      return -1; 

   return ((ev.ts - qbeg_ts1_) >> EVQ_BKT_SHIFT) & (EVQ_BKTS-1);
   // Because of this subtraction, the first event will go to q_[0]. If we
   // eliminated this qbeg_ts1_, qbeg_ will need to be initialized differently
   // --- not a big deal, but perhaps a bit more conceptually complex.
}

static bool ready_to_dq(uint64_t cur_ts) {
   return (qbeg_ts_ <= (maxts_ - maxwait_));
}

// Find the bucket for the new event and insert into it.

bool EConsumer::
do_enq(EventInfo& ev) {
   int bucket = get_bucket(ev);
   if (bucket < 0) {
      errPrtf("Immediately processing %s at %lu\n",
              scname[(uint8_t)ev.ev_code], ev.ts);
      procSyscall(ev);
      return false;
   }
   else {
      q_[bucket].push_back(&ev);
      qsize_++;
      return true;
   }
}

// Dequeue the first unprocessed event in the first bucket. If we are past the
// last element in the bucket, advance to the next bucket and reset qbeg_next_
// to point to the beginning of this bucket. Before doing this, we need to first
// sort the bucket. We use a stable sort so that we don't reorder events from
// their reported order unles we have a good reason. (Perhaps we should factor
// CLK_ERR in this, e.g., by ignoring the least significant 5 or 6 bits of the
// timestamp),

EventInfo* EConsumer::
dq() { 
   EventInfo *rv;
   while (qbeg_next_ >= q_[qbeg_].size()) {
      q_[qbeg_].clear();
      qbeg_next_ = 0;
      if (++qbeg_ >= EVQ_BKTS)
         qbeg_ = 0;
      qbeg_ts_ += (1 << EVQ_BKT_SHIFT);
   }

   vector<EventInfo*>& curq = q_[qbeg_];
   if (qbeg_next_ == 0)
      stable_sort(curq.begin(), curq.end(),
           [](const EventInfo* e1, const EventInfo* e2) 
            {return (e1->ts < e2->ts);});

   rv = curq[qbeg_next_++];
   qsize_--;
   return rv;
};

#endif

// The following functions are common across the different queuing approaches.

void EConsumer::
dqAndDo(bool doall) {
   while (qsize_ != 0 && (doall || ready_to_dq(curtime_))) {
      EventInfo& ev = *dq();
      procSyscall(ev);
   }
}

void EConsumer::
enq(SubjInfo* si, int idx) {
   if (si) {
      EventInfo& ev = *si->curEv[idx];
      si->curEv[idx] = si->curEv.back(); // Remove the event from the subject's
      si->curEv.pop_back();              // event queue.

#ifndef USE_SEQNUM
      if (qbeg_ts1_ == 0) // One-time initialization (on the very first event)
         qbeg_ts1_ = qbeg_ts_ = 
            ((ev.ts - maxwait_/2)>> EVQ_BKT_SHIFT) << EVQ_BKT_SHIFT;
#endif

      // Free a processed event. Other than this, completely ignore it.
      if (ev.status == INJECTED_EXIT) {
         free(ev);
         return;
      }

      if (ev.ts >= si->exitTime) {
         if (ev.ts >= si->exitTime+20e6)
            errPrtf("tid %d: %s's timestamp %gms past exit, forcing before\n",
              si->tid, scname[(int)ev.ev_code], (ev.ts-si->exitTime)/1e6);
         nforced_earlier++;
         ev.ts = si->exitTime-1;
      }
      else {
         maxts_ = max(ev.ts, maxts_);
         if (ev.ts > si->lastEvTime)
            si->lastEvTime = ev.ts;
      }

      dqAndDo();
      do_enq(ev);
   }
};


#define countRdable(ct, width) countReadable(ct, width).data()

template <class K, class V> void 
prtMap(unordered_map<K, V> ht, bool sortByCount,
       std::function<const char*(K)> str, 
       std::function<unsigned short(V)> count) {
    vector<pair<const char*, unsigned>> entries(ht.size());
    unsigned sz=0;
    for (auto kv: ht) {
      const char* s = str(get<0>(kv));
      if (s) entries[sz++] = pair(s, count(get<1>(kv)));         
    }

    if (sortByCount)
      sort(&entries[0], &entries[sz], 
           [](auto k1, auto k2) {
              return (get<1>(k1) > get<1>(k2) || 
                      (get<1>(k1)==get<1>(k2) && 
                       (strcmp(get<0>(k1),get<0>(k2)) < 0)));
           });
    else sort(&entries[0], &entries[sz], 
              [](auto k1, auto k2){return (strcmp(get<0>(k1),get<0>(k2)) < 0);});

    for (auto kf: entries) 
       fprintf(stderr, "%5s: %s\n", countRdable(get<1>(kf), 1), get<0>(kf));
    fputc('\n', stderr);
}

extern int width;

void EConsumer::
prtSum() {
  std::function<const char*(StrId)> sf = [this] (StrId s) {return this->str(s);};
  if (prtFiles_) {
    fprintf(stderr, "******** Files with access counts ********\n");
    std::function<unsigned short(MFUData<Obj*, unsigned short>)>
      cf = [] (MFUData<Obj*, unsigned short> md) {return md.count();};
    prtMap(nm2oi_map.htab(), sortByFreq_, sf, cf);
  }
  if (prtEP_) {
    fprintf(stderr, "******** Endpoints with access counts ********\n");
    std::function<unsigned short(MFUData<MFUVoid, unsigned>)>
      cf = [] (MFUData<MFUVoid, unsigned> md) {return md.count();};
    prtMap(ePs.htab(), sortByFreq_, sf, cf);
  }

  fprintf(stderr, "############################# Summary from Consumer "
          "############################\n");
  fprintf(stderr, "Call: %s Err: %s, Out-of-order >1musec: %.g%% "
          ">1msec %.g%% RD/WR: %s\n", countRdable(nsucc+nfailed,1),
          countRdable(nfailed,1), 1e2*noutoforder/nsucc, 1e2*nmajoroo/nsucc, 
          countRdable(nreadwr,1));
   if (tooLateEvent+tooEarlyEvent+ncollisions+nbadcollisions > 0)
      fprintf(stderr, "Collisions: %ld (%ld unresolved) Events reported too"
              " late: %ld\n", ncollisions , nbadcollisions,
              tooLateEvent);
   //fprintf(stderr, ", unknown rms: %ld\n", countRdable(nunkrms,3));
  prtSortedCounts(succ_count, scname, 255, "Scall", "Counts of Syscalls", width);
  prtSortedCounts(fail_count, scname, 255, "Scall", "Error returns", width);
  prtSortedCounts(err_type, errcode, 255, "Errno", "Error Types", width);
  fprintf(stderr, "***********************************************************"
          "*********************\n");
  fprintf(stderr, "Subjects: Preexisting: %ld (%ld created) Forks: %ld "
          "(threads=%ld forced=%ld)\n", nsubj-(nprocs+nthreads), npresubj, 
          nprocs+nthreads, nthreads, injected_clone_entries);
  if (procopen > 0)
     fprintf(stderr, "/PROC/PID %ld (%ld err, %ld unusual) "
             "/FD %ld (%ld err) STAT: %ld (%ld err)\n", 
             procopen, procopenerr+procopenerr1+procreaderr+piderr,
             procreaderr+procopenerr1+piderr,
             procfdquery, procfderr, statquery, staterrs);
  if (nchildret)
     fprintf(stderr, "***** UNEXPECTED nchildret=%ld\n", nchildret);
  if (clones_wo_returns)
     fprintf(stderr, "***** UNPROCESSED CLONES=%ld\n", clones_wo_returns);
  if (noutofseq*10000 > nsucc) // 0.01%
     fprintf(stderr, "***** UNEXPECTED out of sequence records=%.g%%\n", 
             (noutofseq*1e2)/nsucc);
  if (nforced_earlier*10000 > nsucc) // 0.01%
     fprintf(stderr, "***** UNEXPECTED %ld calls forced earlier\n", 
             nforced_earlier);
  if (expired_events*10000 > nsucc) // 0.01%
     fprintf(stderr, "***** UNEXPECTED %ld unmatched events expired\n", 
             expired_events);
  fprintf(stderr, "Filenames resolved: %s, pre-existing: %s, unresolved: %s\n",
          countRdable(nffound, 1), countRdable(nfforced, 1), 
          countRdable(nfmissing, 1));
   fprintf(stderr, "FDs resolved: %s, unresolved: %s, ignored unresolves: %s\n",
           countRdable(nresolved, 1), countRdable(nunresolved, 1),
           countRdable(uncounted_unres, 1));
   fprintf(stderr, "Endpoints ipv4: %s, ipv6: %s, local: %s, netlink: %s, "
           "unspec: %s, unhandled: %s\n", countRdable(ninetep, 1),
           countRdable(ninet6ep, 1), countRdable(nlocalep, 1),
           countRdable(nnetlinkep, 1), countRdable(nunspecep, 1),
           countRdable(nerrorep, 1));
/*
   fprintf(stderr, "Histogram on #iterations for enq\n";
   searchlen.print(cerr);
   fprintf(stderr, "Histogram on #iterations for dq\n";
   dqlen.print(cerr);
   fprintf(stderr, "Histogram on backward time drifts (out-of-time-order-events)\n";
   oohg.print(cerr);
   fprintf(stderr, "Histogram of oldEvTimeDiff\n";
   oldEvTimeDiff.print(cerr);
*/
}
