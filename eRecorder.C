#include "eRecorder.h"
#include "eConsumer.h"
#include "eauditk.h"

#ifdef FULL_HOST
#include "HostExt.h"
class DummyExt: public HostExt {
   uint64_t tagComparator(uint64_t dst, uint64_t src, uint8_t type) {
      return 0;
   };
  void printTags(uint64_t tags, bool cit) {cout << endl;};
};
DummyExt dmext;
#endif

static PrincipalId remPrinc_;

ERecorder::ERecorder(const char *fn, const vector<unsigned> &ipaddr,
                     const vector<unsigned> &netmasks,
                     const vector<unsigned> &netaddrs): EClient(nullptr) {
#ifdef FULL_HOST
   host_ = new Host("test", boottime/1000, &dmext, Host::RECORD, fn);
#else
   host_ = new RecOnlyHost(fn, ipaddr, netmasks, netaddrs, 1000); 
#endif

   // @@@@ It is unclear that Host uses remote principal info in a meaningful
   // @@@@ way. We assign tags based on IP addresses, so the address is the only
   // @@@@ thing that likely matters. So, lets try using same remprinc for all.
   remPrinc_ = host_->addRemotePrincipal(0, 0, IPADDR);
};

ERecorder::~ERecorder() { 
#ifdef FULL_HOST
   extern bool host_dump;
   if (host_dump) {
      cerr << "***************************** Full Graph from Host "
       << "****************************";
      host_->printall();
   }
   extern bool host_summary;
   if (host_summary) {
      cerr << "******************************* Summary from Host "
       << "******************************";
      host_->printSum();
   }
#endif

   delete host_; 
};

static StrId 
mkcmdln(const char* const* argv, const char* const* envp, Host* h) {
   unsigned la = 0, le = 0;
   if (argv)
      for (unsigned j=0; argv[j]; j++)
         la += strlen(argv[j]) + 1;
   if (envp)
      for (unsigned j=0; envp[j]; j++)
         le += strlen(envp[j]) + 2;

   auto q = (char*)alloca(la+le+10);
   char* p = q;
   if (la)
      for (unsigned j=0; argv[j]; j++) {
         if (j) *p++ = ' ';
         p = stpcpy(p, argv[j]);
      }
   if (le) {
      p = stpcpy(p, " ; envp=");
      for (unsigned j=0; envp[j]; j++) {
         if (j) {*p++ = ';'; *p++ = ';';}
         p = stpcpy(p, envp[j]);
      }
   }
   *p++ = '\0';
   return h->create(q);
}

long ERecorder::
existingSubj(const Subj* s, uint64_t ts) {
   PrincipalId prid = 
      host_->addLocalPrincipal(UId(s->uid), GId(s->gid), PASSWORD);
   const char* argv[MAX_ARG];
   const char* const* sargv = s->argv();
   argv[0] = host_->str(s->exe->nm);
   unsigned j=1;
   if (sargv[0])
      for (; j < MAX_ARG && sargv[j]; j++) 
         argv[j] = sargv[j];
   argv[j] = 0;
   auto cmdln = mkcmdln(argv, s->envp(), host_);
   auto rv = host_->preExistingSubj(s->tid, prid, cmdln, s->ptid, ts/1000); 
   return rv.id();
}

void ERecorder::
existingObj(const Subj* s, const Obj* o, uint64_t ts) {
   assert_abort(o->objtype == FILET);
   auto mo = const_cast<Obj*>(o);
   PrincipalId prid = 
      host_->addLocalPrincipal(UId(mo->uid), GId(mo->gid), PASSWORD);
   Permission perm(mo->mode);
   mo->oid = host_->preExistingFile(mo->nm, prid, ts/1000, perm).id();
}

long ERecorder::
clone(const Subj *parent, const Subj *child, int flg, uint64_t ts) {
//   cerr << "clone ptid=" << parent->tid << ", chtid=" << child->tid 
//        << ", psiid=" << SubjInstId(parent->id).id() << endl;
   return host_->clone(SubjInstId(parent->id), child->tid, flg, ts/1000).id();
   // We used to omit calls to Host for threads. Not sure if anything will break
   // now (since we are treating thread creation liks process creation).
}

void ERecorder::
execve(const Subj *s, const Obj *o, int flags, uint64_t ts) {
   auto cmdln = mkcmdln(s->argv(), s->envp(), host_);
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   host_->execve(SubjInstId(s->id), cmdln, ObjInstId(o->oid), ts/1000);
};

void ERecorder::
exit(const Subj *s, long stat, uint64_t ts) {
   host_->exit(SubjInstId(s->id), ts/1000);
}

void ERecorder::
kill(const Subj *sender, const Subj* target, int signal, long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
ptrace(const Subj *tracer, const Subj* tracee, int request,
                     long rv, uint64_t ts) {
   host_->inject(SubjInstId(tracer->id), SubjInstId(tracee->id), ts/1000);
}

void ERecorder::
setuid(const Subj *s, long euid, long ruid, long suid, long ret, uint64_t ts) {
   PrincipalId prid = 
      host_->addLocalPrincipal(UId(euid), GId(s->gid), PASSWORD);
   host_->setuid(SubjInstId(s->id), prid, ts/1000);
}

void ERecorder::
setgid(const Subj *s, long egid, long rgid, long sgid, long ret, uint64_t ts) {
   PrincipalId prid = 
      host_->addLocalPrincipal(UId(s->uid), GId(egid), PASSWORD);
   host_->setuid(SubjInstId(s->id), prid, ts/1000);
}

// For files as well as other object types, we suffix the ID to name to avoid
// confusion between distinct objects that happen to have the same name. For
// remote objects, we also suffix the time epoch, currently, 10 mins. (Note that
// time is no longer to generate id's in eaudit.) 
//
// There are two things Host does with remote names that we are not sticking by
// here: (a) use of remote principal derived from IP address, (b) use of two
// unidirectional objects per connection instead of one bidirectional object.
// For (a), as noted above, Host does not seem to use the remote principal info.
// For (b), the original motivation was that the two directions of a connection
// are truly independent of each other: all information flows must take place
// through the subject at the other end. However, if we used a single object,
// then, there will be information flow between a send and a receive operation
// *without* going through any subject. This is plain wrong. So, why do we go
// with the wrong model now?
//
//  -- for the common case of non-shared connections, the phantom flow has no
//     bad effect since it only causes a flow from a subject to itself.
//
//  -- for shared connections, say, multiple clients sharing a connection to the
//     same server, phantom flows will matter --- especially in cases where the
//     server is trusted to prevent information flow from one client to another.
//     But we think that shared connections don't arise much. Since the object
//     name includes the ID, and the ID is derived from the addresses of both
//     end points of a connection, this scenario will likely end up being many
//     distinct connections to the server rather than one shared connection.
//     *BUT WE SHOULD VERIFY THIS*
//
//  -- for a while, with eaudit, we have disabled the "SPLIT_BIDIRECTIONAL"
//     ifdef. There was only a minuscule difference in data reduction. (But
//     this says nothing about the loss of accuracy in tracing back.)

// @@@@ Clean up ID_FORMAT. If often repeats id and is unreadable. (THE RIGHT
// @@@@ SOLUTION is to store the id separately in the record file.)

void ERecorder::
createObj(const Obj* o, int uid, int gid, uint64_t ts) {
#define ID_FORMAT ";%lu"
   auto mo = const_cast<Obj*>(o);
   const char* nm = host_->str(o->nm);
   char temp[strlen(nm) + 32];
   NodeType nt = FILE_;
   if (o->objtype == PIPET)
      nt = PIPE;
   else if (o->objtype == SOCKETT) {
      nt = INET;
      uint32_t hrs = ((unsigned)(ts / 6e11)) & 0xffffffff; // 10 minutes
      sprintf(temp, "%s@%d" ID_FORMAT, nm, hrs, o->id);
      auto name = host_->create(temp);
      mo->oid = host_->createObj(name, remPrinc_, ts/1000, 0, 
                                 Permission(0), nt).id();
      return;
   }

   sprintf(temp, "%s" ID_FORMAT, nm, o->id);
   auto name = host_->create(temp);
   const auto& princ = host_->addLocalPrincipal(UId(uid), GId(gid), PASSWORD);
   mo->oid = host_->createObj(name, princ, ts/1000, 0, 
                              Permission(o->mode), nt).id();
}

void ERecorder::
accept(const Subj *s, const Obj *remote, int fd, long rv, uint64_t ts) {
   // We should create a new object even a old one exists.
   createObj(const_cast<Obj*>(remote), 0, 0, ts);
}

void ERecorder::
bind(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   // nothing to do
};

void ERecorder::
connect(const Subj *s, const Obj *remote, int fd, long rv, uint64_t ts) {
   // We should create a new object even a old one exists.
   createObj(remote, 0, 0, ts);
}

void ERecorder::
sendto(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   /* Host does not support yet. We could model as a connect followed
      by a write, but that was not done in previous versions of eConsumer */
}

void ERecorder::
recvfrom(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   /* Host does not support yet. We could model as a connect followed
      by a read, but that was not done in previous versions of eConsumer */
}

void ERecorder::
socket(const Subj *s, int fmly, int  type, int proto, long rv, uint64_t ts) {
   /* Host doesn't care */
}

void ERecorder::
pipe(const Subj* s, int fd0, int fd1, uint64_t ts) {
   /* Host doesn't care */
}

void ERecorder::
sockpair(const Subj* s, int fd0, int fd1, uint64_t ts) {
   /* Host doesn't care */
}

void ERecorder::
dup(const Subj *s, int fd1, int fd2, uint64_t ts) {
   /* Host doesn't care */
}

// open, close, read, write, etc.
void ERecorder::
open(const Subj *s, const Obj *o, int flags, int mode, int rv, uint64_t ts) {
   if (o->oid == nulloiid_i) {
      // Based on the logic of eConsumer, this can happen only if the object
      // was created by this open. Host cares in this case, and wants to see
      // a create operation. 
      auto mo = const_cast<Obj*>(o);
      mo->oid = host_->create(SubjInstId(s->id), FILE_, o->nm, 
                              Permission(mode), ts/1000).id();
   }
   /* Otherwize, Host doesn't care */
}

void ERecorder::
close(const Subj *s, int fd, uint64_t ts) {
   /* Host doesn't care */
}

void ERecorder::
truncate(const Subj *s, const Obj* o, long len, long rv, uint64_t ts, int fd) {
   /* Host doesn't care */
}

void ERecorder::
mkdir(const Subj *s, StrId nm, int mode, long rv, uint64_t ts) {
   host_->create(SubjInstId(s->id), FILE_, nm, Permission(mode), ts/1000);
}

void ERecorder::
mknod(const Subj *s, StrId nm, int mode, int dev, long rv, uint64_t ts) {
   /* Host doesn't care */
}

void ERecorder::
read(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   host_->read(SubjInstId(s->id), ObjInstId(o->oid), rv, ts/1000);
}

void ERecorder::
write(const Subj *s, const Obj *o, int fd, long rv, uint64_t ts) {
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   host_->write(SubjInstId(s->id), ObjInstId(o->oid), rv, ts/1000);
}

void ERecorder::
vmsplice(const Subj *s, const Obj* o, int fd, long rv, uint64_t t) {
   /* should probably be expressed using read/write */
}

void ERecorder::
mmap(const Subj *s, const Obj *o, long addr, long len, 
                     int prot, int flags, long rv, uint64_t ts) {
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   host_->mmap(SubjInstId(s->id), ObjInstId(o->oid), Permission(prot), ts/1000);
}

void ERecorder::
mprotect(const Subj *s, long addr, long len, int prot, 
                         long rv, uint64_t ts) {
   // @@@@ Need to deal with loading. Current implementation of mprotect
   // @@@@ in host does not do this.
}

   // link, rename, remove, etc.
void ERecorder::
link(const Subj* s, const Obj* oldobj, StrId newnm, int flags, 
     long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
symlink(const Subj* s, const Obj* oldobj, StrId newnm, long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
rename(const Subj* s, const Obj* oldobj, StrId newnm, int flags,
                         long rv, uint64_t ts) {
   if (oldobj->oid == nulloiid_i)
      createObj(oldobj, oldobj->uid, oldobj->gid, ts);
   host_->rename(SubjInstId(s->id), ObjInstId(oldobj->oid), newnm, ts/1000);
}

void ERecorder::
unlink(const Subj* s, const Obj* o, long rv, uint64_t ts) {
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   host_->remove(SubjInstId(s->id), ObjInstId(o->oid), ts/1000);
}

// chdir, chmode, etc.

void ERecorder::
chdir(const Subj *s, const Obj* o, long rv, uint64_t ts, int fd) {
   /* Host doesn't care */
}

void ERecorder::
chmod(const Subj *s, const Obj *o, int mode, long rv, uint64_t ts, int fd) {
  if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
  host_->chmod(SubjInstId(s->id), ObjInstId(o->oid), Permission(mode), ts/1000);
}

void ERecorder::
chown(const Subj *s, const Obj *o, int user, int grp, int flags, 
      long rv, uint64_t ts) {
   if (o->oid == nulloiid_i)
      createObj(o, o->uid, o->gid, ts);
   auto princ = host_->addLocalPrincipal(UId(user), GId(grp), PASSWORD);
   host_->chown(SubjInstId(s->id), ObjInstId(o->oid), princ, ts/1000);
}

void ERecorder::
init_module(const Subj* s, StrId params, long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
finit_module(const Subj* s, const Obj* oi, int fd, 
                     StrId params, int flags, long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
mount(const Subj *s, StrId devName, StrId dirName, 
                      StrId fdtype, long flags, long rv, uint64_t ts) {
   /* Host doesn't support */
}

void ERecorder::
umount(const Subj *s, StrId nm, long flags, long rv, uint64_t ts) {
   /* Host doesn't support */
}
