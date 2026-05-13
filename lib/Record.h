#ifndef RECORD_H
#define RECORD_H

#include <stdio.h>

#ifndef RECORD_NO_IDX
template <class C> void
safeAsg(vector<C>& v, uint64_t idx, const C& elem, uint64_t nullidx) {
   if (idx != nullidx) {
      uint64_t s = v.size();
      if (idx < s) v[idx] = elem;
      else if (idx == s) v.push_back(elem);
      else {
        dbgMsg(cout<<"safeAssign called with index " << idx << " > size " << s);
         for (uint64_t i=s; i < idx; i++)
            v.emplace_back();
         v.push_back(elem);
      }
   }
}
#else
#define nulloiid_i (1ul << 48)
#define nullsiid_i (1ul << 48)
#define nulloiid  ObjInstId(nulloiid_i)
#define nullsiid  SubjInstId(nullsiid_i)
#define ObjInstId  BaseIdType<uint64_t, nulloiid_i, 1>
#define SubjInstId BaseIdType<uint64_t, nullsiid_i, 2>
#endif

class Record {
 private:
   bool record_;
   bool popened_;
   bool suspendRecord_[3];
   int suspStkTop_;
   char* recFN_;
   ostream* os_;
   FILE* ofp_;

 protected:
   vector<ObjInstId> oidrv_;
   vector<SubjInstId> sidrv_;
   uint64_t oopCount_, sopCount_;

 private:
   vector<uint64_t> oiidDefIdx_, siidDefIdx_;
   // @@@@ We should add a similar mechanism for StrId and PrincipalId. This way,
   // RecOnlyHost and the real Host do not have to agree on exact values of these
   // ids. For instance, you can write a RecOnlyHost that forgets StrIds after
   // a while and hence recreates the same string again and again. This is 
   // particularly important if the audit log is split into many files, and the
   // RecOnlyHost invoked independently on each log file. TBD.

 protected:
   Record();
   ~Record();

   void startRecording(const char *of, uint64_t rounding=0);
   void finishRecording();
   void checkPoint(const char* chkptFN, ostream& os);

   bool record() const { return record_ && !recordingSuspended();};
   bool recordingSuspended() const { return suspendRecord_[suspStkTop_]; };
   void suspendRecord() {
      assert_abort(++suspStkTop_ < 3);
      suspendRecord_[suspStkTop_] = true; 
   };
   void resumeRecord() { assert_abort(suspStkTop_-- > 0);};

   template <class IdClass> 
   uint64_t idx(IdClass s, const vector<uint64_t>& idDefIdx) const { 
#ifdef RECORD_NO_IDX
      return s.id();
#else
      return idDefIdx[s.id()];
#endif
   };

   template<class IdClass>
   void recrv(IdClass i, vector<uint64_t>& idDefIdx, 
              vector<IdClass>& idrv, uint64_t& ct) {
#ifndef RECORD_NO_IDX
      if (i.isNull()) return;
      if (record_) 
         safeAsg(idDefIdx, i.id(), ct++, i.null().id()); 
      else idrv.push_back(i);
#endif
   }

   void recrv(SubjInstId s) { recrv(s, siidDefIdx_,  sidrv_,   sopCount_); };
   void recrv( ObjInstId o) { recrv(o, oiidDefIdx_,  oidrv_,   oopCount_); };

   void recAddUser(UId uid, const char* name);
   void recAddGroup(GId gid, const char* name, const vector<UId>& mems);
   void recCreateStr(const char* s);
   void recAddLocalPrincipal(UId uid, GId gid, AuthType a1, AuthType a2);
   void recAddRemotePrincipal(unsigned ipaddr, uint16_t port, 
                             AuthType a1, AuthType a2);
   void recAddRemotePrincipal(StrId cert, uint16_t port, AuthType a1);

   void doRec(const char* opnm, const initializer_list<uint64_t>& args, 
              uint64_t ts_us, SubjInstId inSubj, ObjInstId inobj = nulloiid, 
              SubjInstId outSubj=nullsiid, ObjInstId outObj=nulloiid,
              SubjInstId inSubj2=nullsiid);

   void recCreate(SubjInstId s, NodeType nt, StrId name, Permission perm, 
                  uint64_t ts_us, ObjInstId rv);
   void recCreateObj(StrId name, PrincipalId owner, Permission perm, 
                     NodeType nt, bool force, uint64_t ts_us, ObjInstId rv);
   void recPreExistingSubj(int mypid, PrincipalId owner, StrId cmd, 
                           int parent_pid, uint64_t ts_us, bool isThread, 
                           SubjInstId rv);

   void recClone(SubjInstId parent, int childpid, uint32_t flags, bool isUnit, 
                 uint64_t ts_us, SubjInstId rv);
   void recExecve(SubjInstId s, StrId name, ObjInstId bin, uint64_t ts_us);
   void recExit(SubjInstId s, /*int32_t stat,*/ uint64_t ts_us);
   /*void recWait(SubjInstId waitingSubj, SubjInstId exitingSubj, 
     int32_t exitStatus, uint64_t ts_us);
     void recKill(SubjInstId sender, SubjInstId target, int32_t signal, 
     uint64_t ts_us);
   */
   void recSetuid(SubjInstId s, PrincipalId npid, uint64_t ts_us);

   void recChown(SubjInstId s, ObjInstId o, PrincipalId npid, uint64_t ts_us);
   void recChmod(SubjInstId s, ObjInstId o, Permission p, uint64_t ts_us);
   void recMmap(SubjInstId s, ObjInstId o, Permission p, uint64_t ts_us);
   void recMprotect(SubjInstId s, ObjInstId o, Permission p, uint64_t ts_us);
   void recRemove(SubjInstId s, ObjInstId o, uint64_t ts_us);
   void recRename(SubjInstId s, ObjInstId oldobj, StrId newname, uint64_t ts_us, 
                  StrId oldname);

   void recOpen(SubjInstId s, ObjInstId o, uint32_t flags, uint64_t ts_us);
   void recRead(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts_us);
   void recSubjRead(SubjInstId s, SubjInstId ss, uint64_t ts_us);
   void recLoadlib(SubjInstId s, ObjInstId o, uint64_t ts_us);
   void recInject(SubjInstId s, SubjInstId ss, uint64_t ts_us);
   void recWrite(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts_us);
   // void recTruncate(SubjInstId s, ObjInstId o, uint32_t len, uint64_t ts_us);
   void recClose(SubjInstId s, ObjInstId o, uint64_t ts_us);
};

#endif
