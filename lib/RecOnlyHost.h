#ifndef REC_ONLY_HOST_H
#define REC_ONLY_HOST_H

#define RECORD_ONLY
#define RECORD_NO_IDX
#include "Common.h"
#include "Principal.h"

#include "Record.h"

class RecOnlyHost: public Record {
   PrincipalId root_;
   PrincipalId defaultUser_;

   vector<unsigned> myAddr_;
   vector<unsigned> myEnterpNetMasks_;
   vector<unsigned> myEnterpNetAddr_;
   IdMap<StrId, const char*> strtab_;
   IdMap<PrincipalId, Principal> princtab_;

   unordered_map<const char*, StrId> strmap_;
   unordered_map<Principal, PrincipalId> princMap_;

public:
   RecOnlyHost(const char* fn, const vector<unsigned>& ipaddr, // My IP addresses
               const vector<unsigned>& netmasks, // Netmasks for my enterprise
               const vector<unsigned>& netaddrs,  // Networks in my enterprise
               uint64_t rounding=0
               ): myAddr_(ipaddr), myEnterpNetMasks_(netmasks), 
                  myEnterpNetAddr_(netaddrs) {
      myAddr_.push_back((127u<<24)+1); // 127.0.0.1
      assert_abort(netmasks.size() == netaddrs.size());

      startRecording(fn, rounding);

      create("_init");
      sopCount_++; // Ensures SubjInstId of 0 is not used (reserved for initd)

      assert_abort(addUser(UId(0), "root"));
      assert_abort(addGroup(GId(0), "root", vector<UId>{UId(0)}));
      root_ = addLocalPrincipal(UId(0), GId(0), AUTH_OS);

      // @@@@ Questionable assumption, as uid or gid 65534 may already be used
      assert_abort(addUser(UId(-2), "defaultUser"));
      assert_abort(addGroup(GId(-2), "defaultGrp", vector<UId>{UId(-2)}));
      defaultUser_ = addLocalPrincipal(UId(-2), GId(-2), PASSWORD);
   };

   ~RecOnlyHost() {
      princMap_.clear();
      princtab_.clear();
      strmap_.clear();
      for (uint64_t i = 0; i < strtab_.size(); i++) 
         delete [] strtab_[StrId(i)];
      strtab_.clear();
   };

   const char* str(StrId i) const {return (i==StrId::null())? "" : strtab_[i];};
   StrId strId(const char* s) const {
      if (!s) return invalidStrId;
      auto it = strmap_.find(s);
      if (it != strmap_.end()) return it->second; else return invalidStrId;
   };

   StrId create(const char* s) {
      // if (!s) s = ""; // Let us treat a null pointer as empty string
      StrId rv = strId(s);
      if (!s) return rv;
      if (rv == invalidStrId) {
         unsigned n = strlen(s)+1;
         char* s1 = new char [n];
         strncpy(s1, s, n);
         rv = strtab_.alloc();
         strtab_[rv] = s1;
         strmap_[s1] = rv;
         recCreateStr(s);
      }
      return rv;
   };

   const Principal* principal(PrincipalId i) const { return &princtab_[i]; };
   PrincipalId princId(const Principal* p) const {return princtab_.getIndex(p);};

#include "HostIfc.h"

   SubjInstId preExistingSubj(int mypid, PrincipalId owner, StrId cmd,
                              int parent_pid, uint64_t ts_us, bool isThread=0);
   SubjInstId clone(SubjInstId parent, int childpid, uint32_t flags, 
                    uint64_t ts, bool isThrd=false);
};

#endif
