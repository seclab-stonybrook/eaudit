#ifndef EPRINTER_H
#define EPRINTER_H

#include <stdio.h>
#include "eClient.h"

class EPrinter: public EClient {
 private:
   bool use_seqnum, prt_musec_ts, prt_existingsubj, prt_existingobj;
   FILE *ofp;

 public:
   EPrinter(EConsumer *ec, FILE *fp=stdout, bool use_seq=false, 
       bool prt_musecs=false, bool prt_existing_subj=false,
       bool prt_existing_obj=false): EClient(ec),
          use_seqnum(use_seq), prt_musec_ts(prt_musecs), 
          prt_existingsubj(prt_existing_subj),
          prt_existingobj(prt_existing_obj), ofp(fp) {};

   ~EPrinter() { fclose(ofp); };

   void prt_ts_and_pid(const Subj* s, uint64_t ts);

   long existingSubj(const Subj* s, uint64_t ts);
   void existingObj(const Subj* s, const Obj* o, uint64_t ts);

   // Process operations
   long clone(const Subj *parent, const Subj *child, int flags, 
                      uint64_t ts);
   void execve(const Subj *s, const Obj *o, int flags, 
                       uint64_t ts);
   void exit(const Subj *s, long flags, uint64_t ts);

   void kill(const Subj *sender, const Subj* target, int signal,
                     long rv, uint64_t ts);
   void ptrace(const Subj *tracer, const Subj* tracee, int request,
                     long rv, uint64_t ts);

   void setuid(const Subj *s, long euid, long ruid, long suid, 
                       long ret, uint64_t ts);
   void setgid(const Subj *s, long egid, long rgid, long sgid, 
                       long ret, uint64_t ts); // and setgid syscalls.

   // Network operations and IPC
   void accept(const Subj *s, const Obj *remote, int fd, 
                       long rv, uint64_t ts);
   void bind(const Subj *s, const Obj *o, int fd, 
                     long rv, uint64_t ts);
   void connect(const Subj *s, const Obj *remote, int fd,
                        long rv, uint64_t ts);
   void sendto(const Subj *s, const Obj *o, int fd, 
                       long rv, uint64_t ts);
   void recvfrom(const Subj *s, const Obj *o, int fd, 
                         long rv, uint64_t ts);
   void socket(const Subj *s, int family, int  type, int protocol, 
                       long rv, uint64_t ts);
   virtual void pipe(const Subj* s, int fd0, int fd1, uint64_t ts);
   virtual void sockpair(const Subj* s, int fd0, int fd1, uint64_t ts);
   void dup(const Subj *s, int fd1, int fd2, uint64_t ts);

   // open, close, read, write, etc.
   void open(const Subj *s, const Obj *o, int flags, int mode, 
                     int rv, uint64_t ts);
   void close(const Subj *s, int fd, uint64_t ts);
   void truncate(const Subj *s, const Obj* o, long len, long rv, 
     uint64_t ts, int fd); // fd is valid for ftruncate, -1 for truncate
   void mkdir(const Subj *s, StrId nm, int mode, long rv, uint64_t ts);
   void mknod(const Subj *s, StrId nm, int mode, 
                      int dev, long rv, uint64_t ts);

   void read(const Subj *s, const Obj *o, int fd,  
                     long rv, uint64_t ts);
   void write(const Subj *s, const Obj *o, int fd, 
                      long rv, uint64_t ts);
   void vmsplice(const Subj *s, const Obj* o, int fd, 
                         long rv, uint64_t t);

   void mmap(const Subj *s, const Obj *o, long addr, long len, 
                     int prot, int flags, long rv, uint64_t ts);
   void mprotect(const Subj *s, long addr, long len, int prot, 
                         long rv, uint64_t ts);

   // link, rename, remove, etc.
   void link(const Subj* s, const Obj* oldobj, StrId newnm,
                     int flags, long rv, uint64_t ts);
   void symlink(const Subj* s, const Obj* oldobj, StrId newnm,
                         long rv, uint64_t ts);
   void rename(const Subj* s, const Obj* oldobj, StrId newnm, int flags,
                         long rv, uint64_t ts);
   void unlink(const Subj* s, const Obj* o, long rv, uint64_t ts);
   // void rmdir(const Subj* s, const Obj* o, long rv, uint64_t ts);

   // chdir, chmode, etc.
   void chdir(const Subj *s, const Obj* o, long rv, uint64_t ts, 
      int fd); // fd is valid for fchdir, -1 for chdir
   void chmod(const Subj *s, const Obj *o, int mode, long rv, 
      uint64_t ts, int fd); // fd is valid for fchmod, -1 for chmod
   void chown(const Subj *s, const Obj *o, int user, int grp, int flags,
      long rv, uint64_t ts); // fd is valid for fchown, -1 for chown

   // other administrative operations
   void init_module(const Subj* s, StrId params, long rv, uint64_t ts);
   void finit_module(const Subj* s, const Obj* oi, int fd, 
                     StrId params, int flags, long rv, uint64_t ts);
   void mount(const Subj *s, StrId devName, StrId dirName, 
                      StrId fdtype, long flags, long rv, uint64_t ts);
   void umount(const Subj *s, StrId nm, long flags, 
                       long rv, uint64_t ts);
};
#endif
