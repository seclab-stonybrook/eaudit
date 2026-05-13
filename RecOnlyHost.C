#include "RecOnlyHost.h"

#include "Principal.C"

#include "Record.C"

#define recret(y, x) y; return x

ObjInstId RecOnlyHost::
createObj(StrId cname, PrincipalId owner, uint64_t ts, bool *flag,
            Permission perm, NodeType nt) {
   ObjInstId oi(oopCount_++);
   recret(recCreateObj(cname, owner, perm, nt, (flag && *flag), ts, oi), oi);
}

pair<ObjInstId, ObjInstId> RecOnlyHost::
createRemObjPair(uint32_t localIP, uint16_t localPort, uint32_t remIP, 
                 uint16_t remPort, uint64_t ts_us, bool *created) {
   char nm[1024];
   const char *proto="IP";
   for (auto ip: myAddr_) {
      if (ip == remIP) {
         // Both endpoints are local, return a file object instead
         proto = "LOCAL";
         if (localIP < remIP || (localIP == remIP && localPort < remPort))
            sprintf(nm, "%s:%x:%d:%x:%d", proto, localIP, localPort,
                    remIP, remPort);
         else sprintf(nm, "%s:%x:%d:%x:%d", proto, remIP, remPort,
                      localIP, localPort);
         StrId n = create(nm);
         ObjInstId o = createObj(n, defaultUser_, ts_us, created, Permission(0),
                                 INTRAHOST_CONN);
         return make_pair(o, o);
      }
   }

   ResType rt = INET_R;
   for (unsigned j=0; j < myEnterpNetMasks_.size(); j++) 
      if ((remIP & myEnterpNetMasks_[j]) == myEnterpNetAddr_[j]) {
        rt = ENTERP_R;
        break;
      }

   if (rt == ENTERP_R) { 
      // Enterprise endpoint: generate a name that would be identical
      // on both Hosts representing the two host machines
      if (localIP < remIP || (localIP == remIP && localPort < remPort))
         sprintf(nm, "%s:%x:%d:%x:%d", proto, localIP, localPort,
                 remIP, remPort);
      else sprintf(nm, "%s:%x:%d:%x:%d", proto, remIP, remPort,
                   localIP, localPort);
   }
   else {
      uint32_t hrs = (ts_us/(10*60*1000*1000)) & 0xffffffff; // 10 minutes
      sprintf(nm, "%s:%x:%d.%dH", proto, remIP, remPort, hrs);
   }

   StrId n = create(nm);
   PrincipalId remPrinc = addRemotePrincipal(remIP, 0, // treat all ports for
    (rt == ENTERP_R)? ENTERPRISE_ENDPOINT: TCP); // one IP addr as one principal
   ObjInstId src = createObj(n, remPrinc, ts_us, created, Permission(0),
                       nodeType(rt, false, false, false, true));
   ObjInstId sink = createObj(n, remPrinc, ts_us, created, Permission(0),
                       nodeType(rt, false, false, true, false));
   return make_pair(src, sink);
}

SubjInstId RecOnlyHost::
preExistingSubj(PId mypid, PrincipalId owner, StrId cmd, PId parent_pid,
                    uint64_t ts_us, bool isThread) {
   SubjInstId child(sopCount_++);
   recret(recPreExistingSubj(mypid.id(), owner, cmd, parent_pid.id(), ts_us, 
                             isThread, child), child);
}

SubjInstId RecOnlyHost::
preExistingSubj(int mypid, PrincipalId owner, StrId cmd, int parent_pid, 
                uint64_t ts_us, bool isThread) {
   SubjInstId child(sopCount_++);
   recret(recPreExistingSubj(mypid, owner, cmd, parent_pid, ts_us, isThread, 
                             child), child);
}

bool RecOnlyHost::
addUser(UId uid, const char* name) {
   recret(recAddUser(uid, name), true);
}

bool RecOnlyHost::
addGroup(GId gid, const char* name, const vector<UId> &mems) {
   recret(recAddGroup(gid, name, mems), true);
}

PrincipalId RecOnlyHost::
addLocalPrincipal(UId uid, GId gid, AuthType a1, AuthType a2) {
   PrincipalId rv;
   assert_abort(a1 <= MAX_USER_AUTH);
   Principal princ(uid, gid, HostId::null(), a1, a2);
   auto it = princMap_.find(princ);
   if (it == princMap_.end()) {
      PrincipalId id = princtab_.alloc();
      Principal *p = &princtab_[id];
      new (p) Principal(princ);
      princMap_[princ] = id;
      rv = id;
      recAddLocalPrincipal(uid, gid, a1, a2);
   }
   else rv = it->second;
   return rv;
}

PrincipalId RecOnlyHost::
addRemotePrincipal(uint32_t ipaddr, uint16_t port, AuthType a1, AuthType a2) {
   PrincipalId rv;
   assert_abort(a1 > MAX_USER_AUTH && a1 <= MAX_REMOTE_AUTH);
   Principal princ(ipaddr, port, a1, a2);
   auto it = princMap_.find(princ);
   if (it == princMap_.end()) {
      PrincipalId id = princtab_.alloc();
      Principal *p = &princtab_[id];
      new (p) Principal(princ);
      princMap_[princ] = id;
      rv = id;
      recAddRemotePrincipal(ipaddr, port, a1, a2);
   }
   else rv = it->second;
   return rv;
}

PrincipalId RecOnlyHost::
addRemotePrincipal(StrId cert, uint16_t port, AuthType a1) {
   assert_abort(a1 > MAX_USER_AUTH && a1 <= MAX_REMOTE_AUTH);
   PrincipalId rv;
   Principal princ(cert, port, a1);
   auto it = princMap_.find(princ);
   if (it == princMap_.end()) {
      PrincipalId id = princtab_.alloc();
      Principal *p = &princtab_[id];
      new (p) Principal(princ);
      princMap_[princ] = id;
      rv = id;
      recAddRemotePrincipal(cert, port, a1);
   }
   else rv = it->second;
   return rv;
}

SubjInstId RecOnlyHost::
clone(SubjInstId parent, PId childpid, uint32_t flags, uint64_t ts, bool isThrd) {
   SubjInstId child(sopCount_++);
   recret(recClone(parent, childpid.id(), flags, isThrd, ts, child), child);
}

SubjInstId RecOnlyHost::
clone(SubjInstId parent, int childpid, uint32_t flags, uint64_t ts, bool isThrd){
   SubjInstId child(sopCount_++);
   recret(recClone(parent, childpid, flags, isThrd, ts, child), child);
}

void RecOnlyHost::
execve(SubjInstId parent, StrId cmdln, ObjInstId bin, uint64_t ts) {
   recExecve(parent, cmdln, bin, ts);
}

void RecOnlyHost::
exit(SubjInstId s, /*int32_t stat,*/ uint64_t ts) {
   recExit(s, /*stat,*/ ts);
}

void RecOnlyHost::
setuid(SubjInstId parent, PrincipalId nprinc, uint64_t ts) {
   recSetuid(parent, nprinc, ts);
}

ObjInstId RecOnlyHost::
create(SubjInstId s, NodeType nt, StrId name, Permission perm, uint64_t ts) {
   ObjInstId no(oopCount_++);
   recret(recCreate(s, nt, name, perm, ts, no), no);
}

void RecOnlyHost::
open(SubjInstId s, ObjInstId o, uint32_t flags, uint64_t ts) {
   recOpen(s, o, flags, ts);
}

void RecOnlyHost::
chown(SubjInstId s, ObjInstId o, PrincipalId nowner, uint64_t ts) {
   recChown(s, o, nowner, ts);
}

void RecOnlyHost::
chmod(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   recChmod(s, o, p, ts);
}

void RecOnlyHost::
mprotect(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   recMprotect(s, o, p, ts);
}

void RecOnlyHost::
mmap(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   recMmap(s, o, p, ts);
}

void RecOnlyHost::
remove(SubjInstId s, ObjInstId o, uint64_t ts) {
   recRemove(s, o, ts);
}

void RecOnlyHost::
rename(SubjInstId s, ObjInstId o, StrId newnm, uint64_t ts, StrId onm) {
   recRename(s, o, newnm, ts, onm);
}

void RecOnlyHost::
read(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts, bool *useful) {
   recRead(s, o, buflen, ts);
}

void RecOnlyHost::
subjRead(SubjInstId s, SubjInstId ss, uint64_t ts, bool *useful) {
   recSubjRead(s, ss, ts);
}

void RecOnlyHost::
loadlib(SubjInstId s, ObjInstId o, uint64_t ts, bool calledFromExec, 
        bool *useful) {
   recLoadlib(s, o, ts);
}

void RecOnlyHost::
inject(SubjInstId s, SubjInstId ss, uint64_t ts, bool *useful) {
   recInject(s, ss, ts);
}

void RecOnlyHost::
write(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts, bool *useful) {
   recWrite(s, o, buflen, ts);
}

void RecOnlyHost::
close(SubjInstId s, ObjInstId o, uint64_t ts) {
   recClose(s, o, ts);
}
