#ifndef E_CONSUMER_H
#define E_CONSUMER_H

#include <stack>
#include "eauditk.h"
#include "eClient.h"
// Every client of eConsumer must implement the interface defined in eClient.h
// and enroll with eConsumer to receive these events

using namespace std;

class SubjInfo;
class ERecorder;

enum LookupOpt: char {IGNORE, QUERY_OS, CREATE_BEST_EFFORT};

union EvArg {
   union {
      int i;
      unsigned u;
      StrId nm;
      StrId ep;
   } u32[2];
   long l;
   uint64_t ul;

   EvArg() {ul=0;};
   EvArg(const EvArg& o) {ul = o.ul;};
};

enum SysCallStat: char {
   NEITHER, ENTRY_SEEN, EXIT_SEEN, INJECTED_EXIT, BOTH_SEEN, 
};

struct EventInfo {
   char ev_code; // We use the exit codes from logcode.h
   SysCallStat status;
   uint16_t seqnum;
   int fd;
   long id;
   uint64_t ts;
   EvArg arg[4]; // Used for arguments as well as return values
   SubjInfo* si;
};

class EConsumer {
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wsubobject-linkage"
 public:
   enum CreationFlag: char {OLD, MAYBE_NEW, NEW};
   struct NmOpt {
      CreationFlag create_flag;
      char otype;
      LookupOpt opt;

      NmOpt(CreationFlag cf, ObjType otype_, LookupOpt opt_):
         create_flag(cf), otype(otype_), opt(opt_) {};
   };

 private:
   bool prtFiles_, prtEP_, sortByFreq_;
   uint64_t curtime_;
   stack<EventInfo*> freeEv_;
   vector<EClient*> clients_;
   vector<bool>         own_; // own_[i] => delete clients_[i] in destructor

 public:
   EConsumer(bool lookupProc, bool prtFiles, bool prtEP, bool sortByFreq,
             ERecorder* eh=nullptr);
   ~EConsumer();

   void enroll(EClient* c, bool take_ownership); // if so, delete at the end
   const char* str(StrId s) const;
   unsigned nargs(StrId* argv) const;
   // const char* const* toargv(StrId*) const;

   void finalize();
   void prtSum();

   void cur_time(uint64_t ts) { curtime_ = ts;}
   void accRcvfPeer(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
           int fd, long id, const uint8_t *saddr, unsigned salen, long rv);
                   // accept, recvfrom, getpeername
   void bind(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
                const uint8_t *saddr, unsigned salen, long rv);
   void chdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                  const char* fn, long rv);
   void fchdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
               int fd, long id, long rv);
   void chmodat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                int fd, long id, const char* fn, int mode, long rv);
   void fchmod(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
               long id, int mode, long rv);
   void chownat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
      long id, const char* fn, long user, long grp, long flgs, long rv);
   void fchown(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
               long id, long user, long grp, long rv);
   void ent_clone(char sc,uint16_t sn,uint64_t ts, int tid, int pid, long flgs);
   void close(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
              long unrep_rd, long unrep_wr, long rv);
   void connect(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
                long id, const uint8_t *saddr, unsigned salen, long rv);
   void dup(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
            long rv);
   void ent_execveat(char sc, uint16_t sn, uint64_t ts, int tid, int pid,
       int fd, long id, long flags, const char* fn, const char* const argv[], 
       const char* const envp[]);
   void ent_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int code);
   void init_module(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                    const char* params, long rv);
   void finit_module(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                     int fd, long id, const char* params, int flags, long rv);
   void ent_kill(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int pid1, 
                 int tid1, int sig);
   void linkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd1, 
               long id1, const char* fn1, int fd2, long id2, const char* fn2, 
               long flags, long rv);
   void symlinkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                  const char* fn1, int fd, long id, const char* fn2, long rv);
   void mkdirat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
               int fd, long id, const char* fn, int mode, long rv);
   void mknodat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
               int fd, long id, const char* fn, int mode, int dev, long rv);
   void mmapex(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long id, 
             long addr, long len, int prot, int flags, long rv);
   void mount(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
         const char* s, const char *dst, const char* fstp, long flags, long rv);
   void mprotect(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
             long addr, long len, int prot, long rv);
   void openat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int at_fd, 
      const char* fn, int flags, int mode, int rv, long at_id, long ret_id);
   void pipe(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                 bool is_sock, int fd1, int fd2);
   void ent_ptrace(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                   long request, int pid1);
   void read(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
                 long id, long rv);
   void renameat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd1,
                 long id1, const char*fn1, int fd2, long id2, 
                 const char* fn2, long flags, long rv);
   void rmdir(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                  const char* fn, long rv);
   void sendto(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd,
                const uint8_t *saddr, unsigned salen, long rv);
   void setgid(char sc, uint16_t sn, uint64_t ts,int tid,int pid,int rgid,
                   int egid, int sgid, long rv);
   void setuid(char sc, uint16_t sn, uint64_t ts,int tid,int pid,int ruid,
                   int euid, int suid, long rv);
   void socket(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int family,
               int type, int protocol, long rv);
   void vmsplice(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                   int fd, long id, long rv);
   void truncate(char sc, uint16_t sn, uint64_t ts,int tid,int pid, 
                     const char*fn, long len, long rv);
   void ftruncate(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                  int fd, long id, long len, int rv);

   void umount(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
               const char* s, long flags, long rv);
   void unlinkat(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
                 long id, const char*fn, long rv);
   void write(char sc, uint16_t sn, uint64_t ts, int tid, int pid, int fd, 
                  long id, long rv);
   
   void clone_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
      int par_tid, int rv, int uid, int gid, long cgroup); // fork/clone
   void exec_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
      int par_tid, int rv, int uid, int gid, long cgroup);
   void sc_exit(char sc, uint16_t sn, uint64_t ts, int tid, int pid, long rv);

private:
   void procSyscall(EventInfo& ev);
   SubjInfo* createExistingSubj(int tid, int pid, uint64_t ts, LookupOpt opt);
   EventInfo* dq();
   void dqAndDo(bool doAll=false);
   bool do_enq(EventInfo& ev);
   void enq(SubjInfo* si, int idx);

   EventInfo* newEvInfo();
   void free(EventInfo&);
   
   void doaccept(EventInfo& ev);
   void dobind(EventInfo& ev);
   void dochdir(EventInfo& ev);
   void dofchdir(EventInfo& ev);
   void dochmod(EventInfo& ev);
   void dofchmod(EventInfo& ev);
   void dochown(EventInfo& ev);
   void dofchown(EventInfo& ev);
   void doclone(EventInfo& ev);
   void doclose(EventInfo& ev);
   void doconnect(EventInfo& ev);
   void dodup(EventInfo& ev);
   void doexecve(EventInfo& ev);
   void doexit(EventInfo& ev);
   void doexitgrp(EventInfo& ev);
   void dogetpeer(EventInfo& ev);
   void doinitmod(EventInfo& ev);
   void dofinitmod(EventInfo& ev);
   void dokill(EventInfo& ev);
   void dolink(EventInfo& ev);
   void dosymlink(EventInfo& ev);
   void domkdir(EventInfo& ev);
   void domknod(EventInfo& ev);
   void dommap(EventInfo& ev);
   void domount(EventInfo& ev);
   void domprotect(EventInfo& ev);
   void doopen(EventInfo& ev);
   void dopipeopen(EventInfo& ev);
   void doptrace(EventInfo& ev);
   void doreadwr(EventInfo& ev, bool rd);
   void dorecvfrom(EventInfo& ev);
   void dorename(EventInfo& ev);
   void dormdir(EventInfo& ev);
   void dosendto(EventInfo& ev);
   void dosetgid(EventInfo& ev);
   void dosetuid(EventInfo& ev);
   void dosocket(EventInfo& ev);
   void dosplice(EventInfo& ev);
   void dovmsplice(EventInfo& ev);
   void dotruncate(EventInfo& ev);
   void doftruncate(EventInfo& ev);
   void doumount(EventInfo& ev);
   void dounlink(EventInfo& ev, bool prtRmdir = false);

//   void dofinalize(EventInfo& ev);

private:
   SubjInfo* getSubj(int tid, int pid, uint64_t ts, 
                     int uid=INVAL_UID, int gid=INVAL_UID); 
   StrId createObjNmAsStr(SubjInfo* si, int fd, uint64_t id);
   const char* createObjNm(SubjInfo* si, int fd, uint64_t id);

   Obj* createSocket(SubjInfo* si, uint64_t id, StrId nm, uint64_t ts);
   Obj* nm2Obj(SubjInfo* si, StrId nm, uint64_t ts, NmOpt opts, 
               uint64_t id=nullid);
   Obj* nm2ObjAt(SubjInfo* si, int at_fd, long at_id, StrId nm, 
                         uint64_t ts, NmOpt opts, uint64_t id=nullid);
   Obj* resolveId(SubjInfo* si, int fd, long id, uint64_t ts, NmOpt opt);
   StrId fullpath(SubjInfo *si, int at_fd, uint64_t at_id, StrId fn,
                  uint64_t ts, NmOpt opt);
   
   StrId getEp(const uint8_t *saddr, int salen);
   SubjInfo* preOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                   int& idx);
   SubjInfo* postOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                    long rv, int& idx);
   SubjInfo* prePostOp(char sc, uint16_t sn, uint64_t ts, int tid, int pid, 
                     long rv, int& idx);
   void processExpired(vector<EventInfo*>& evs);
};
//#pragma GCC diagnostic pop

#endif
