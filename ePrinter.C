#include "ePrinter.h"
#include "prthelper.h"
#include <fcntl.h>
#include "eauditk.h"
#include "eConsumer.h"

/*Every print function consists of trailing false. This false is added to 
pass is_tampered flag to prt_* helper functions.*/

void EPrinter::
prt_ts_and_pid(const Subj *s, uint64_t ts) {
   prttspid(ts, s->pid, s->seqnum, 0, use_seqnum, 0, prt_musec_ts, ofp);
   if (s->tid != s->pid)
      fprintf(ofp, "tid=%u: ", s->tid);
}

long EPrinter::
existingSubj(const Subj* s, uint64_t ts) {
   if (prt_existingsubj) {
      prt_ts_and_pid(s, ts);
      prt_execve(AT_FDCWD, 0, 0, s->exe->name(), s->argv(), s->envp(), 
                 ofp, "running_proc");
   }
   return -1;
}

void EPrinter::
existingObj(const Subj* s, const Obj* o, uint64_t ts) {
   if (prt_existingobj) {
      prt_ts_and_pid(s, ts);
      fprintf(ofp, "object(name=%s", o->name());
      if (o->id != nullid)
         fprintf(ofp, ", id=%lu", o->id);
      if (o->uid != s->uid && o->uid != INVAL_UID)
         fprintf(ofp, ", uid=%d", o->uid);
      if (o->gid != s->gid && o->gid != INVAL_UID)
         fprintf(ofp, ", gid=%d", o->gid);
      if (o->mode != 07777)
         fprintf(ofp, ", mode=%o", o->mode);
      if (o->mtime != 0)
         fprintf(ofp, ", mtime=%u", o->mtime);
      fprintf(ofp, ")");
   }
}

// Process operations
long EPrinter::
clone(const Subj *parent, const Subj *child, int flags, uint64_t ts) {
   prt_ts_and_pid(parent, ts);
   prt_clone(flags, child->tid, ofp, false);
   return -1;
}

void EPrinter::
execve(const Subj *s, const Obj *o, int flags, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_execve(AT_FDCWD, 0, 0, s->exe->name(), s->argv(), s->envp(), ofp, false);
}

void EPrinter::
exit(const Subj *s, long flags, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   if (strnlen(s->syscall, 7) < 5)
      prt_exit(flags, ofp, false);
   else prt_exitgrp(flags, ofp, false);
}

void EPrinter::
kill(const Subj *sender, const Subj* target, int sig, long rv, uint64_t ts) {
   prt_ts_and_pid(sender, ts);
   if (rv == 0)
      prt_kill_no_ret(target->pid, target->tid, sig, ofp, false);
   else prt_kill(target->pid, target->tid, sig, rv, ofp, false);
}

void EPrinter::
ptrace(const Subj *tracer, const Subj* tracee, int request,
       long rv, uint64_t ts) {
   prt_ts_and_pid(tracer, ts);
   prt_ptrace(tracee->tid, request, ofp, false);
}

void EPrinter::
setuid(const Subj *s, long euid, long ruid, long suid, long ret, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_setuid(euid, ruid, suid, ret, ofp, false);
}

void EPrinter::
setgid(const Subj *s, long egid, long rgid, long sgid, long ret, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_setgid(egid, rgid, sgid, ret, ofp, false);
}

// Network operations and IPC
void EPrinter::
accept(const Subj *s, const Obj *remote, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_saddr("accept", fd, remote->id, rv, remote->name(), ofp);
}

void EPrinter::
bind(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_saddr("bind", fd, o->id, rv, o->name(), ofp);
}

void EPrinter::
connect(const Subj *s, const Obj *remote, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_saddr("connect", fd, remote->id, rv, remote->name(), ofp);
}

void EPrinter::
sendto(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_saddr("sendto", fd, 0 /*o->id*/, rv, o->name(), ofp);
   // @@@@ no id in sendto
}

void EPrinter::
recvfrom(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_saddr("recvfrom", fd, o->id, rv, o->name(), ofp);
}

void EPrinter::
socket(const Subj *s, int family, int  type, int proto, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_socket(family, type, proto, ofp, false);
}

void EPrinter::
pipe(const Subj* s, int fd0, int fd1, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_pipe_spair(PIPE_EX, fd0, fd1, ofp, false);
}

void EPrinter::
sockpair(const Subj* s, int fd0, int fd1, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_pipe_spair(SOCKPAIR_EX, fd0, fd1, ofp, false);
}

void EPrinter::
dup(const Subj *s, int fd1, int fd2, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_dup("dup", fd1, fd2, ofp, false);
}

// open, close, read, write, etc.
void EPrinter::
open(const Subj *s, const Obj *o, int flags, int mode, int rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_open(AT_FDCWD, o->name(), flags, mode, rv, 0, o->id, ofp, false);
}

void EPrinter::
close(const Subj *s, int fd, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_close(fd, 0, 0, ofp, false);
}

void EPrinter::
truncate(const Subj *s, const Obj* o, long len, long rv, uint64_t ts, int fd) {
   prt_ts_and_pid(s, ts);
   prt_truncate(o->name(), len, rv, ofp, false);
}

void EPrinter::
mkdir(const Subj *s, StrId nm, int mode, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_mkdir(AT_FDCWD, 0, ec()->str(nm), mode, rv, ofp, false);
}

void EPrinter::
mknod(const Subj *s, StrId nm, int mode, int dev, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_mknod(AT_FDCWD, 0, ec()->str(nm), mode, dev, rv, ofp, false);
}

void EPrinter::
read(const Subj *s, const Obj *o, int fd,  long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_read(fd, o->id, rv, ofp, false);
}

void EPrinter::
write(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_write(fd, o->id, rv, ofp, false);
}

void EPrinter::
vmsplice(const Subj *s, const Obj* o, int fd, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_vmsplice(fd, o->id, rv, ofp, false);
}

void EPrinter::
mmap(const Subj *s, const Obj *o, long addr, long len, 
                     int prot, int flags, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_mmap(addr, len, prot, flags, o->id, rv, ofp, false);
}

void EPrinter::
mprotect(const Subj *s, long addr, long len, int prot, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_mprotect(addr, len, prot, rv, ofp, false);
}

// link, rename, remove, etc.
void EPrinter::
link(const Subj* s, const Obj* oldobj, StrId newnm,
                     int flags, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_link(AT_FDCWD, 0, AT_FDCWD, 0, oldobj->name(), 
            ec()->str(newnm), flags, rv, ofp, false);
}

void EPrinter::
symlink(const Subj* s, const Obj* oldobj, StrId newnm, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_symlink(AT_FDCWD, 0, oldobj->name(), ec()->str(newnm), rv, ofp, false);
}

void EPrinter::
rename(const Subj* s, const Obj* oldobj, StrId newnm, int flags,
                         long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_rename(AT_FDCWD, 0, AT_FDCWD, 0, oldobj->name(), 
              ec()->str(newnm), flags, rv, ofp, false);
}

void EPrinter::
unlink(const Subj* s, const Obj* o, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_unlink(AT_FDCWD, 0, o->name(), rv, ofp, false);
}

// void EPrinter::
// rmdir(const Subj* s, const Obj* o, long rv, uint64_t ts) {
//    prt_ts_and_pid(s, ts);
//    prt_rmdir(o->name(), rv, ofp);
// }

// chdir, chmode, etc.
void EPrinter::
chdir(const Subj *s, const Obj* o, long rv, uint64_t ts, int fd) {
   prt_ts_and_pid(s, ts);
   prt_chdir(o->name(), rv, ofp, false);
}

void EPrinter::
chmod(const Subj *s, const Obj *o, int mode, long rv, uint64_t ts, int fd) {
   prt_ts_and_pid(s, ts);
   prt_chmod(AT_FDCWD, 0, o->name(), mode, rv, ofp, false);
}

void EPrinter::
chown(const Subj *s, const Obj *o, int user, int grp, int flags,
      long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_chown(o->name(), user, grp, AT_FDCWD, 0, flags, rv, ofp, false);
}

// other administrative operations
void EPrinter::
init_module(const Subj* s, StrId params, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_init_module(ec()->str(params), rv, ofp, false);
}

void EPrinter::
finit_module(const Subj* s, const Obj* oi, int fd, 
              StrId params, int flags, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_finit_module(ec()->str(params), fd, oi->id, flags, rv, ofp, false);
}

void EPrinter::
mount(const Subj *s, StrId devName, StrId dirName, 
                      StrId fdtype, long flags, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_mount(ec()->str(devName), ec()->str(dirName), ec()->str(fdtype), 
             flags, rv, ofp, false);
}

void EPrinter::
umount(const Subj *s, StrId nm, long flags, long rv, uint64_t ts) {
   prt_ts_and_pid(s, ts);
   prt_umount(ec()->str(nm), flags, rv, ofp, false);
}
