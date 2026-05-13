#ifndef ID_H
#define ID_H

/*******************************************************************************
 * Instead of using pointers, we use Ids. While Ids could be defined to be
 * pointers, their use provides more flexibility to the design. For instance,
 * we can replace them with more compact identifiers that are more
 * space-efficient. Moreover, they could be allocated contiguously in an array,
 * support customized garbage collection techniques, etc. They may also enable
 * better algorithms for "aging" and "purging" old data.
 *
 * The Ids are encapsulated in their own classes so that clients won't see
 * (or be affected by) implementation choices made.
******************************************************************************/

#include <cstdint>
#include <iostream>
#include "Common.h"

using namespace std;

#define SIIDBITS 34
#define OIIDBITS 34

#define SVIDBITS 9
#define OVIDBITS 6

#define MAXIIDBITS cmax(SIIDBITS, OIIDBITS)
#define MAXVIDBITS cmax(SVIDBITS, OVIDBITS)

#define HIDBITS 16 // actually, this can be zero with the distributed design
// (63-MAXIIDBITS-MAXVIDBITS) // 63-34-9 = 20
// all ids plus one flag bit will fit into 64-bits.

static const uint64_t nulloiid_i = (1ul<<OIIDBITS)-1; // max 16B-1
static const uint64_t nullsiid_i = (1ul<<SIIDBITS)-1; // max 16B-1
static const uint16_t nullovid_i = (1<<OVIDBITS)-1;   // max 63
static const uint16_t nullsvid_i = (1<<SVIDBITS)-1;   // max 511
static const uint32_t nullprincid_i = (1<<24)-1;      // max ~16M
static const uint32_t invalidStrId_i = ~0;
static const uint16_t nulluid_i = ~0;
static const uint16_t nullgid_i = ~0;
static const uint16_t nullpid_i = 0;
static const uint16_t nullunitid_i = 0;
static const uint32_t nullhid_i = (1<<HIDBITS)-1; // max 1M-1 hosts
static const uint16_t nullpolid_i = (~(uint16_t)0);

// IMPORTANT: nullId value MUST NOT be used as an index, as we check equality
// with nullId to decide if we have a valid id value or not. The third template
// parameter ensures that two ID's won't be considered type-equivalent.
// Otherwise, the 3rd parameter is unused.
template <typename BaseType, BaseType maxId, int extra=0, BaseType nullId=maxId> 
class BaseIdType {
 private:
   BaseType id_;
 public:
   static BaseIdType max() { return BaseIdType(maxId); };
   static BaseIdType null() { return BaseIdType(nullId); };

   explicit BaseIdType(BaseType s=nullId): id_(s) 
      {assert_fix(s <= maxId, s = maxId);};
   BaseIdType(const BaseIdType& o) {
      id_ = o.id_;
   }

   BaseType id() const {return id_; }
   bool isNull() const { return (id_ == nullId);};
   void set(BaseType v) { id_ = v; }; // Don't check validity, as 
   // caller may want to use invalid values.

   bool operator==(const BaseIdType& t) const { return id_ == t.id_; }
   bool operator!=(const BaseIdType& t) const { return id_ != t.id_; }
   auto operator<=>(const BaseIdType& t) const { return id_ <=> t.id_; }

   const BaseIdType& operator=(const BaseIdType& other) { 
      id_ = other.id_; return *this;
   }
};

template <typename InstId, typename VerId, uint64_t nulliid_, unsigned nullvid_,
   unsigned IIDBITS, unsigned VIDBITS>
class InstVerId {
   VerId vid_;
   uint64_t iid_: IIDBITS;
 public:
   explicit InstVerId(InstId iid, VerId vid): vid_(vid), iid_(iid.id()) {};
   explicit InstVerId(InstId iid, int vid): vid_(vid), iid_(iid.id()) {};
   explicit InstVerId(uint64_t i): vid_(i & ((1<<VIDBITS)-1)), iid_(i>>VIDBITS) {};
   explicit InstVerId():  InstVerId(InstId(nulliid_), VerId(nullvid_)) {};
   explicit InstVerId(InstId iid): InstVerId(iid, VerId(nullvid_)) {};

   static InstId nuliid() { return InstId(nulliid_); };
   static VerId  nulvid() { return VerId(nullvid_); };

   bool isNull() const { return iid_ == nulliid_;};

   void set(InstId iid, VerId vid) { vid_ = vid; iid_ = iid.id(); };
   void set(InstId iid, uint16_t vid) { vid_.set(vid); iid_ = iid.id(); };

   VerId vid() const { return vid_; };
   InstId iid() const { return InstId(iid_); };
   bool operator==(const InstVerId& o) const { 
      return (iid_ == o.iid_ && vid_ == o.vid_); 
   };
   bool operator!=(const InstVerId& o) const { return !operator==(o); };
   uint64_t toul() const { return (iid_<<VIDBITS)|vid_.id(); };
   ostream& print(ostream& os) const { 
      if (iid_ == nulliid_)
         os << "null";
      else os << iid_ << '.' << vid_.id(); 
      return os;
   };
};

typedef BaseIdType<uint64_t, nulloiid_i, 1> ObjInstId;
typedef BaseIdType<uint64_t, nullsiid_i, 2> SubjInstId;
typedef BaseIdType<uint16_t, nullovid_i, 3> ObjVerId;
typedef BaseIdType<uint16_t, nullsvid_i, 4> SubjVerId;
typedef BaseIdType<uint32_t, nullprincid_i, 5> PrincipalId;
typedef BaseIdType<uint32_t, nullprincid_i, 5> PrincipalId;
typedef BaseIdType<uint32_t, invalidStrId_i, 6> StrId;
typedef BaseIdType<uint16_t, nulluid_i, 7, 0> UId;
typedef BaseIdType<uint16_t, nullgid_i, 8, 0> GId;
typedef BaseIdType<uint16_t, 65535, 9, nullpid_i> PId;
typedef BaseIdType<uint16_t, 65535, 10, nullunitid_i> UnitId;
typedef BaseIdType<uint16_t, nullhid_i, 11> HostId;
typedef BaseIdType<uint16_t, nullpolid_i, 12> PolicyId;
typedef InstVerId<ObjInstId, ObjVerId, nulloiid_i, nullovid_i, 
   OIIDBITS, OVIDBITS> ObjId;
typedef InstVerId<SubjInstId, SubjVerId, nullsiid_i, nullsvid_i, 
   SIIDBITS, SVIDBITS> SubjId;

typedef BaseIdType<uint64_t, (1ul<<50), 13> EId;
typedef BaseIdType<uint64_t, (1ul<<50), 14> AlarmId;

inline ostream& operator<<(ostream& os, ObjId oid) { return oid.print(os);};
inline ostream& operator<<(ostream& os, SubjId sid) { return sid.print(os);};

inline ostream& operator<<(ostream& os, ObjInstId oiid) { os<<oiid.id(); return os;};
inline ostream& operator<<(ostream& os, SubjInstId siid) { os<<siid.id(); return os;};

static const PrincipalId nullprincid;
static const SubjId nullsubj;
static const UnitId nullunitid;
static const ObjId nullobj;
static const PrincipalId nullprinc;
static const StrId invalidStrId;
static const PId nullpid;
static const HostId nullhid;
static const PolicyId nullpolid;
static const ObjInstId nulloiid;
static const SubjInstId nullsiid;
static const ObjVerId nullovid;
static const SubjVerId nullsvid;

class GenId {
 public:
   enum IdType: unsigned char {
      ERR, STR, PRINCIPAL, PID, TID, UID, GID, SUBJINST, OBJINST, 
      SUBJECT, OBJECT, EDGE, ALARM
   };

 private:
   IdType type_;
   uint64_t id_: 56;

 public:
   GenId() {type_ = ERR; };
   GenId(StrId i) { str(i); }
   GenId(PrincipalId i) { principal(i); }
   GenId(PId i) { pid(i); }
   GenId(UnitId i) { tid(i); }
   GenId(UId i) { uid(i); }
   GenId(GId i) { gid(i); }
   GenId(SubjId i) { subj(i); }
   GenId(ObjId i) { obj(i); }
   GenId(SubjInstId i) { subjInst(i); }
   GenId(ObjInstId  i) { objInst(i); }

   IdType type() const { return type_; };
   bool isValid() const { return type_ != ERR; };

   void str(StrId i) { type_ = STR; id_ = i.id(); };
   void principal(PrincipalId i) { type_ = PRINCIPAL; id_ = i.id(); };
   void pid(PId i) { type_ = PID; id_ = i.id(); };
   void tid(UnitId i) { type_ = TID; id_ = i.id(); };
   void uid(UId i) { type_ = UID; id_ = i.id(); };
   void gid(GId i) { type_ = GID; id_ = i.id(); };
   void subjInst(SubjInstId i) { type_ = SUBJINST; id_ = i.id(); };
   void  objInst( ObjInstId i) { type_ =  OBJINST; id_ = i.id(); };
   void subj(SubjId i) { type_ = SUBJECT; id_ = (i.toul() & ((1ul<<56)-1)); };
   void  obj( ObjId i) { type_ =  OBJECT; id_ = (i.toul() & ((1ul<<56)-1)); };

   StrId str() const { 
      assert_fix(type_==STR, return invalidStrId); return StrId(id_); 
   };
   PrincipalId principal() const { 
      assert_fix(type_==PRINCIPAL, return nullprinc); return PrincipalId(id_); 
   };
   PId pid() const { 
      assert_fix(type_==PID, return nullpid); return PId(id_); 
   };
   UnitId tid() const { 
      assert_fix(type_==TID, return nullunitid); return UnitId(id_); 
   };
   UId uid() const { 
      assert_fix(type_==UID, return UId(nulluid_i)); return UId(id_); 
   };
   GId gid() const { 
      assert_fix(type_==GID, return GId(nullgid_i)); return GId(id_); 
   };
   SubjInstId subjInst() const { 
      assert_fix(type_==SUBJINST, return nullsiid); return SubjInstId(id_); 
   };
   ObjInstId   objInst() const { 
      assert_fix(type_==OBJINST, return nulloiid); return ObjInstId(id_); 
   };
   SubjId subj() const { 
      assert_fix(type_==SUBJECT, return nullsubj); return SubjId(id_); 
   };
   ObjId obj() const { 
      assert_fix(type_==OBJECT, return nullobj); return ObjId(id_); 
   };
};

static_assert(sizeof(GenId) == sizeof(uint64_t), "fix GenId");

/*
  IdMap maps Ids to Elements using an array representation. So, Ids have to start
  at zero and be contiguous. But we allow holes to be created by freeing Ids. 
  To support this, we keep the free Ids in a linked list, storing the head in 
  freeList_. Operations alloc() and free() can deal with this complexity if
  you free ids. Otherwise, alloc() and free() are very efficient, assigning the
  next available id. freeVec() can return all the freed Ids as a vector.
*/
template <typename IdType, typename ElemType>
class IdMap {
 private:
   vector<ElemType> elems_;
   IdType freeList_;

   static_assert(sizeof(ElemType) >= sizeof(IdType), "ElemType too small");

 public:
   IdMap() { freeList_ = IdType::null(); };

   uint64_t size() const { return elems_.size(); };

   void clear() { freeList_ = IdType::null(); elems_.clear(); };

   IdType alloc() {
      if (freeList_ != IdType::null()) {
         IdType e = freeList_;
         freeList_ = *(IdType*)(&elems_[freeList_.id()]);
         return e;
      }
      else {
         assert_abort(elems_.size() < IdType::max().id());
         elems_.emplace_back();
         return IdType(elems_.size()-1);
      }
   };

   void free(IdType i) {
      assert_abort(i.id() < elems_.size());
      *(IdType*)(&elems_[i.id()]) = freeList_;
      freeList_ = i;
   };

   IdType getIndex(const ElemType* e) const {
     IdType rv(e - &(elems_[0]));
     if (rv.id() >= elems_.size()) {
        errMsg(cout << "getIndex: Pointer argument out of range\n");
        return IdType::null();
     }
     return rv;
   }

   ElemType& operator[](IdType i) {
      uint64_t ii = i.id();
      assert_fix(ii < elems_.size(), assert_abort(elems_.size() > 0); ii = 0);
      return elems_[ii];
   }

   const ElemType& operator[](IdType i) const {
      return const_cast<IdMap<IdType, ElemType>*>(this)->operator[](i);
   }

   // If pointers are stored in the elems_ array, we would like to check if 
   // one of them is valid before attempting to free it. But since we reuse 
   // freed slots in elems_ to maintain a free list of available ids, this 
   // becomes a bit tricky. There is no perfect solution, but we can check if
   // the pointer falls within the range of a valid id. If so, it is unlikely 
   // to be a valid pointer. Note that if the check is used before freeing a
   // pointer, the result of an incorrect answer is a memory leak, which is
   // much more acceptable than an invalid memory access.

   bool isPossiblyFreeablePtr(IdType i) const {
      if (is_pointer_v<ElemType> && (i.id() >= 0) && (i.id() < elems_.size())) {
         IdType possibleId = *(IdType*)elems_[i.id()];
         return (possibleId.id() < 0 || possibleId.id() >= elems_.size());
         // If it looks like a valid id, it is likely storing an id and not
         // a pointer. Say no. If it is outside the range of valid ids, 
         // it could be possibly be OK to free.
      }
      return false;
   }

   vector<uint64_t> freeVec() const {
      vector<uint64_t> rv;
      for (IdType i = freeList_; i != IdType::null(); 
           i = *(IdType*)(&elems_[i.id()])) 
         rv.emplace_back(i.id());
      sort(rv.begin(), rv.end()); 
      return rv;
   }

   void serialize(ostream& os) const {
      vector<uint64_t> frees(freeVec());
      os << frees.size() << ' ';
      for (uint64_t i=0; i < frees.size(); i++)
         os << frees[i] << endl;
      os << endl;
      os << elems_.size() << endl;
      uint64_t i, j;
      for (i = 0, j=0; i < elems_.size(); i++) {
         if (j < frees.size() && i == frees[j]) {
            j++; continue;
         }
         else {
            ::serialize(os, elems_[i]);
            os << endl;
         }
      }
   };

   void deserialize(istream& is) {
      vector<uint64_t> frees;
      uint64_t sz;
      is >> sz;
      char t;
      is.read(&t, 1);
      assert_try(t == ' ');
      for (uint64_t i = 0; i < sz; i++) {
         uint64_t d;
         is >> d;
         frees.emplace_back(d);
      }

      while (1) { // This skip to end-of-line is to maintain compatibility
         is.read(&t, 1); // with pevious version of serialization
         if (t == '\n') break;
      }

      is.putback(t);
         
      is >> sz;
      uint64_t i, j;
      for (i = 0, j = 0; i < sz; i++) {
         elems_.emplace_back(); // @@@@ Base types (eg ptrs) NOT INITIALIZED!
         if (j < frees.size() && i == frees[j]) {
            j++;
            continue;
         }
         is.read(&t, 1);
         assert_try(t == '\n');
         ::deserialize(is, elems_[i]);
      }
      is.ignore(1);

      freeList_ = IdType::null();
      for (i = 0; i < frees.size(); i++)
         free(IdType(frees[i]));
   };
};

namespace std {
   template <> struct hash<UId> {
    public:
      size_t operator()(UId u) const { return u.id()*65539; }
   };

   template <> struct less<UId> {
      bool operator() (const UId& lhs, const UId& rhs) const { return lhs.id()<rhs.id(); }
   };

   template <> struct hash<GId> {
    public:
      size_t operator()(GId u) const { return u.id()*65539; }
   };

   template <> struct less<GId> {
      bool operator() (const GId& lhs, const GId& rhs) const { return lhs.id()<rhs.id(); }
   };

   template <> struct hash<PId> {
    public:
      size_t operator()(PId u) const { return u.id()*65539; }
   };

   template <> struct less<PId> {
   public:
      bool operator() (const PId& lhs, const PId& rhs) const { return lhs.id()<rhs.id(); }
   };

   template <> struct hash<SubjInstId> {
    public:
      size_t operator()(SubjInstId u) const{return (u.id())*((((long)1)<<32)-5);}
   };

   template <> struct hash<ObjInstId> {
    public:
      size_t operator()(ObjInstId u) const {return (u.id())*((((long)1)<<32)-5);}
   };

   template <> struct hash<SubjId> {
    public:
      size_t operator()(SubjId u) const {return (u.toul())*((((long)1)<<32)-5); }
   };

   template <> struct hash<ObjId> {
    public:
      size_t operator()(ObjId u) const { return (u.toul())*((((long)1)<<32)-5); }
   };

   template <> struct hash<StrId> {
    public:
      size_t operator()(StrId u) const { return u.id()*((((long)1)<<32)-5); }
   };

   template <> struct less<StrId> {
   public:
      bool operator() (const StrId& lhs, const StrId& rhs) const { return lhs.id()<rhs.id(); }
   };

   template <> struct hash<PrincipalId> {
    public:
      size_t operator()(PrincipalId u) const{ return u.id()*((((long)1)<<32)-5);}
   };

   template <> struct hash<AlarmId> {
    public:
      size_t operator()(AlarmId u) const{ return u.id()*((((long)1)<<32)-5);}
   };

   template <> struct hash<EId> {
    public:
      size_t operator()(EId u) const{ return u.id()*((((long)1)<<32)-5);}
   };
};

#endif
