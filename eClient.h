#ifndef E_CLIENT_H
#define E_CLIENT_H

#include "Id.h"
#ifndef FULL_HOST
#define nulloiid_i (1ul << 48)
#define nullsiid_i (1ul << 48)
#define nulloiid  ObjInstId(nulloiid_i)
#define nullsiid  SubjInstId(nullsiid_i)
#define ObjInstId  BaseIdType<uint64_t, nulloiid_i, 1>
#define SubjInstId BaseIdType<uint64_t, nullsiid_i, 2>
#endif

class EConsumer;

/*******************************************************************************
 * eConsumer can serve events (aka syscalls) to clients that are registered with
 * it. These clients must derive from this EClient class and override the
 * methods for the subset of events they wish to handle. (For the remaining
 * events, EClient provides a default handler that does nothing.) Each event
 * receives an argument of class Subj that describes the process making this
 * syscall. Most events also take an object argument, described by class Obj.
 * These two classes are defined below, followed by eClient class.
 *
 * Many system calls have variants, e.g., open_at vs open. There may be
 * additional flag arguments. In addition, read and write operations can take
 * place via numerous distinct syscalls. eClient merges them into a single
 * event, with arguments to hold extra information.
 *
 * For syscalls that change something, Subj and Obj arguments report the state
 * before the operation. This way, clients can assess the change that is being
 * made. (For creation operations and operations that set attributes that aren't
 * meaningful to change (e.g., the bind syscall), we return post-state.)
 ******************************************************************************/

class Obj;
constexpr uint64_t nullid = 0; 
struct Subj {
   uint64_t id;         // Forever unique id.
   int tid;             // No two current subjects can have same TID. (Linux
   int pid;             // kernel code calls tid as pid and pid as pgid).
   int ptid;            // Cloner of this subject, matches Linux kernel's view.
   int uid;             // Effective userid and
   int gid;             // Effective group id of the current process
   int seqnum;          // Sequence number of the current event
   const char* syscall; // Current syscall name
   const Obj* cwd;      // Current working directory of subject
   const Obj* exe;      // Subject's executable
   const StrId *args;   // Command line args
   const StrId *envs;   // Environment vars

 protected:
   mutable const char* const* argv_;
   mutable const char* const* envp_;

 public:
   int argc() const;
   int envc() const;
   const char* const* argv() const;
   const char* const* envp() const;

 protected:
   Subj(uint64_t id_, int tid_, int pid_, int ptid_, int uid_, int gid_): 
     id(id_), tid(tid_), pid(pid_), ptid(ptid_), uid(uid_), gid(gid_),seqnum(0),
     syscall(0), cwd(0), exe(0), args(0), envs(0), argv_(0), envp_(0) {
   };

  void cloneargs(const StrId* a);
  void cloneenvs(const StrId* e);

  ~Subj() {};
};

enum ObjType:uint64_t {FILET=1, PIPET, SOCKETT};
struct Obj {
   StrId nm;          // For files, name corresponds to file name. For network
   int uid;           // objects, name specifies the remote endpoint.
   int gid;           // Mode, ownership (uid and gid) and modification time
   unsigned mtime;    // (in seconds) are also reported, but their reliability
   uint64_t id;       // depends on whether OS is queried and if the data is
   uint64_t objtype:3;// enabled on eaudit. id is an almost unique object
   uint64_t mode: 12; // id. (Among a billion distinct files as per the OS, 
   uint64_t oid:  49; // estimated # of collisions in id is about 1.) 

 public:
   const char* name() const;

   Obj(StrId n=StrId(), ObjType ot=FILET, uint64_t id_=0,   // In the absence of
       int u_id=0, int g_id=0,    // other info, default file ownership to root.
       short md=07777, unsigned mtm=0, long oid_=nulloiid_i):
      nm(n), uid(u_id), gid(g_id), mtime(mtm), id(id_), objtype((uint64_t)ot), 
      mode(md), oid((uint64_t)oid_) {};

   // bool operator==(const Obj& o);
   // bool operator!=(const Obj& o) { return !(*this == o); }
   // bool isNull() { return objtype == 0; }
};

class EClient {
   EConsumer* ec_;

public:
   EClient(EConsumer* ec): ec_(ec) {};
   virtual ~EClient() {};

   const EConsumer* ec() { return ec_; };

   // The first registered client should return a valid id. Others are ignored.
   virtual long existingSubj(const Subj* s, uint64_t ts) { return -1; }
   virtual void existingObj(const Subj* s, const Obj* o, uint64_t ts) {}

   // Process operations
   virtual long clone(const Subj *parent, const Subj *child, int flags, 
                      uint64_t ts) { return -1; };
   virtual void execve(const Subj *s, const Obj *o, int flags, 
                       uint64_t ts) {};
   virtual void exit(const Subj *s, long stat, uint64_t ts) {};

   virtual void kill(const Subj *sender, const Subj* target, int signal,
                     long rv, uint64_t ts) {};
   virtual void ptrace(const Subj *tracer, const Subj* tracee, int request,
                     long rv, uint64_t ts) {};

   virtual void setuid(const Subj *s, long euid, long ruid, long suid, 
                       long ret, uint64_t ts) {};
   virtual void setgid(const Subj *s, long egid, long rgid, long sgid, 
                       long ret, uint64_t ts) {}; // and setgid syscalls.

   // Network operations and IPC
   virtual void accept(const Subj *s, const Obj *remote, int fd, 
                       long rv, uint64_t ts) {};
   virtual void bind(const Subj *s, const Obj *o, int fd, 
                     long rv, uint64_t ts) {};
   virtual void connect(const Subj *s, const Obj *remote, int fd,
                        long rv, uint64_t ts) {};
   virtual void sendto(const Subj *s, const Obj *remote, int fd, 
                       long rv, uint64_t ts) {};
   virtual void recvfrom(const Subj *s, const Obj *remote, int fd, 
                         long rv, uint64_t ts) {};
   virtual void socket(const Subj *s, int family, int  type, int protocol, 
                       long rv, uint64_t ts) {};
   virtual void pipe(const Subj* s, int fd0, int fd1, uint64_t ts) {};
   virtual void sockpair(const Subj* s, int fd0, int fd1, uint64_t ts) {};
   virtual void dup(const Subj *s, int fd1, int fd2, uint64_t ts) {};

   // open, close, read, write, etc.
   virtual void open(const Subj *s, const Obj *o, int flags, int mode, 
                     int rv, uint64_t ts) {};
   virtual void close(const Subj *s, int fd, uint64_t ts) {};
   virtual void truncate(const Subj *s, const Obj* o, long len, long rv, 
     uint64_t ts, int fd) {}; // fd is valid for ftruncate, -1 for truncate
   virtual void mkdir(const Subj *s, StrId name, int mode, 
                      long rv, uint64_t ts) {};
   virtual void mknod(const Subj *s, StrId nm, int mode, 
                      int dev, long rv, uint64_t ts) {};

   virtual void read(const Subj *s, const Obj *o, int fd,  
                     long rv, uint64_t ts) {};
   virtual void write(const Subj *s, const Obj *o, int fd, 
                      long rv, uint64_t ts) {};
   virtual void vmsplice(const Subj *s, const Obj* o, int fd, 
                         long rv, uint64_t t) {};
   // We shd map vmsplice into a read or write operation ...

   virtual void mmap(const Subj *s, const Obj *o, long addr, long len, 
                     int prot, int flags, long rv, uint64_t ts) {};
   virtual void mprotect(const Subj *s, long addr, long len, int prot, 
                         long rv, uint64_t ts) {};

   // link, rename, remove, etc.
   virtual void link(const Subj* s, const Obj* oldobj, StrId newnm,
                     int flags, long rv, uint64_t ts) {};
   virtual void symlink(const Subj* s, const Obj* oldobj, StrId newnm,
                         long rv, uint64_t ts) {};
   virtual void rename(const Subj* s, const Obj* oldobj, StrId newnm,
                       int flags, long rv, uint64_t ts) {};
   virtual void unlink(const Subj* s, const Obj* o, long rv, uint64_t ts) {};

   // chdir, chmode, etc.
   virtual void chdir(const Subj *s, const Obj* o, long rv, uint64_t ts, 
      int fd) {}; // fd is valid for fchdir, -1 for chdir
   virtual void chmod(const Subj *s, const Obj *o, int mode, long rv, 
      uint64_t ts, int fd) {}; // fd is valid for fchmod, -1 for chmod
   virtual void chown(const Subj *s, const Obj *o, int user, int grp, int flags,
      long rv, uint64_t ts, int fd) {}; // fd is valid for fchown, -1 for chown

   // other administrative operations
   virtual void init_module(const Subj* s, StrId params, 
                            long rv, uint64_t ts) {};
   virtual void finit_module(const Subj* s, const Obj* oi, int fd, 
                             StrId params, int flags, long rv, uint64_t ts) {};
   virtual void mount(const Subj *s, StrId devName, StrId dirName, 
                      StrId fdtype, long flags, long rv, uint64_t ts) {};
   virtual void umount(const Subj *s, StrId nm, long flags, 
                       long rv, uint64_t ts) {};
};
#endif
