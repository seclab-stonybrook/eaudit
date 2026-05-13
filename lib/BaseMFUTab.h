#include <assert.h>
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <functional>
#include <utility>

#include "Base.h"
#include "STLutils.h"
#include "MFUData.h"

#ifdef MFU_DBG
extern bool dbg ;
extern long insct;
extern long nvisit;
#endif

// This file actually defines two variants of MFUTable and MFUSet. The first
// is a simple version that uses access counts to prune out least frequently
// accessed entries. It resets access counts to 1 after each prune. The
// second version uses an exponentially decaying access count. Two additional
// parameters, decayrate and decaygen are needed, with the semantics that
// access counts will be scaled by decayrate every decaygen microseconds. 
// All access operations take a clock (in microseconds) as an additional
// operator. We are using some cpp tricks to generate two distinct classes
// from this one file. We may want to change this in the future to have
// the decaying version be a subclass of the base version.

// @@@@ Add optional flag to lookups so that they don't increment access counts

// @@@@ Because hashtable lookups are dramatically slower when they get larger
// @@@@ due to cache effect, it seems better to make this hierarchical: An
// @@@@ MFUTab of size N has a nested MFUTab of size N/16, for instance. At the
// @@@@ leaf level, we have a simply array of size, say, 4. The idea is that we
// @@@@ will first check the nested table first, so that the most frequently 
// @@@@ accessed elements will be in the inner tables, which is likely to reside
// @@@@ in a faster cache. OTOH, it is possible that access to frequently 
// @@@@ accessed entries would already be fast, without such nesting. Think thru.

template<class KeyType, class DataType, class CounterType=unsigned short> 

class BaseMFUTable {
 public:
   typedef MFUData<DataType, CounterType> Data;
   typedef std::function<void(KeyType, Data, bool beingRemoved)> ShrinkFnType;
   static_assert(sizeof(unsigned)==4 && sizeof(long)==8,
                 "Only supports 4-byte integer and 8-byte long");
   static_assert(sizeof(CounterType)<=sizeof(unsigned),"CounterType too large");

 private:
   long ownsPtr_:1;
#ifdef DECAY_MFU
   long tsshift_:6;
   long lastDecay_us_:56;
   unsigned decayGen_;
   unsigned decayFac_; // Every decayTime_, scale counts by decayFac_/2^32
#endif
   unsigned maxSize_; // Max entries, auto increased as pinned entries are added.
   unsigned misses_;  // Misses and accesses are scaled so that their ratio
   unsigned accesses_;// is correct. Accesses include lookups AND inserts.
   unsigned maxCount_; // >= all counts, but may not equal max since
   ShrinkFnType shrink;// we don't do any thing on removal.
   unordered_map<KeyType, Data> htab_;

   typedef 
   BaseMFUTable<KeyType, DataType, CounterType> Self;

 public:

#ifndef DECAY_MFU
   BaseMFUTable(): htab_() { // MUST call init to set maxSz and possibly other
      init(0, {}, true);     // parameters before an object returned by
   }                         // this constructor can be used.

   BaseMFUTable(unsigned maxsz, ShrinkFnType sf={}) {
      init(maxsz, sf);
   }

   BaseMFUTable(unsigned maxSz, int takeOwnershipOfPtrData): htab_() {
      init(maxSz, takeOwnershipOfPtrData);
   }

   void init(unsigned maxsz, ShrinkFnType sf={}) {
      maxSize(maxsz);
      ownsPtr_ = false;
      maxCount_ = 0;
      misses_ = accesses_ = 0;
      shrink = sf;
   }

   void init(unsigned maxSz, int takeOwnershipOfPtrData) {
      maxSize(maxSz);
      maxCount_ = 0;
      misses_ = accesses_ = 0;
      if ((ownsPtr_ = 
           (is_pointer<DataType>::value && takeOwnershipOfPtrData)))
         shrink = [](KeyType k, Data d, bool b) {
                     if (b) delete d.data();
                  };
   }

#define updateAcc(x, y, z) updateAcc(x, y)
#define lookup(a, b) lookup(a)
#define lookupData(a, b) lookupData(a)
#define update(a, b, c, d) update(a, b, d)
#define insert(a, b, c, d, e) insert(a, b, d, e)
#define insertWithCount(a, b, c, d, e) insertWithCount(a, b, c, e)

#else
   BaseMFUTable(): htab_() { // MUST call init to set maxSz and possibly other
      init(0, 0, 0, 0, {}, true); // parameters before an object returned by
   }                              // this constructor can be used.

   BaseMFUTable(unsigned maxsz, double decayFac, long decayGen_us, 
            long clock_us, ShrinkFnType sf={}) {
      init(maxsz, decayFac, decayGen_us, clock_us, sf);
   }

   BaseMFUTable(unsigned maxSz, int takeOwnershipOfPtrData, double decayFac, 
       long decayGen_us, long clock_us): htab_() {
      init(maxSz, takeOwnershipOfPtrData, decayFac, decayGen_us, clock_us);
   }

   void init(unsigned maxsz, double decayFactor, long decayGen_us, 
            long clock_us, ShrinkFnType sf={}) {
      maxSize(maxsz);
      ownsPtr_ = false;
      maxCount_ = 0;
      misses_ = accesses_ = 0;
      decayFac(decayFactor);
      decayGen(decayGen_us);
      lastDecay_us_ = clock_us;      
      shrink = sf;
   }

   void init(unsigned maxSz, int takeOwnershipOfPtrData, double decayFactor, 
       long decayGen_us, long clock_us) {
      maxSize(maxSz);
      maxCount_ = 0;
      misses_ = accesses_ = 0;
      decayFac(decayFactor);
      decayGen(decayGen_us);
      lastDecay_us_ = clock;      
      shrink = {};
      if ((ownsPtr_ = 
           (is_pointer<DataType>::value && takeOwnershipOfPtrData)))
         shrink = [](KeyType k, Data d, bool b) {
                     if (b) delete d.data();
                  };
   }

#endif

   ~BaseMFUTable() {
      removeAll();
   }

   const unordered_map<KeyType, Data>& htab() const { return htab_;};

   unsigned size() const { return htab_.size(); };

   unsigned maxSize() const { return maxSize_; }

   double missRate() const { return ((double)misses_)/accesses_;};
   double hitRate() const { return 1.0-missRate();};

#ifdef DECAY_MFU
   long decayGen() const { return decayGen_;};
   double decayFac() const { return ((double)decayFac_)/(1l<<32); };
#endif

 private:
   void maxSize(unsigned maxSz) 
     { assert_fix(maxSz >= 8, maxSz=256); maxSize_ = maxSz; }

#ifdef DECAY_MFU
   void decayGen(long dcgen) {
      if (dcgen < (1l<<32))
         tsshift_ = 0;
      else tsshift_ = 32-__builtin_clz(dcgen);
      decayGen_ = dcgen>>tsshift_;
   }

   void decayFac(double df) { decayFac_ = df*(1l<<32);};
#endif

 public:
   Data* lookup(KeyType k, long clock_us) {
      auto it = htab_.find(k);
      if (it == htab_.end()) {
         updateAcc(1, 1, clock_us);
         return nullptr;
      };

      updateAcc(1, 0, clock_us);
      it->second.__count(it->second.count()+1);
      if (it->second.count() > maxCount_)
         if (++maxCount_ > Data::maxCount()-3) // must be -3 to avoid 
            halveCount();      // overflows while halving.

      return &it->second;
   }

   DataType lookupData(KeyType k, long clock_us) {
      Data* d = lookup(k, clock_us);
      if (d)
         return d->data();
      else return DataType();
   }

   bool update(KeyType k, const DataType& d, long clock_us, bool pin=false) {
      return insert(k, d, clock_us, pin, true);
   }

   bool insert(KeyType k, const DataType& d, long clock_us, 
               bool pin=false, bool update=false) {
   /* JUST MODIFIED TO PERMIT UPDATE, may not be tested.
   // *** No updates supported --- you can insert the same (key, data) pair
   // multiple times, but if you make an initial call (k, d1) and then (k, d2),
   // then d2 will be ignored; the value d1 will continue to be in the map.
   */
#ifdef MFU_DBG
      insct++;
#endif
      auto it = htab_.find(k);
      if (it != htab_.end()) {
         updateAcc(1, 0, clock_us);
         it->second.__count(it->second.count()+1);
         if (it->second.count() > maxCount_)
            if (++maxCount_ > Data::maxCount()-3)
               halveCount();
         if (update)
            it->second.data(d);
         return false;
      }
      else {
         updateAcc(1, 1, clock_us);
         if (pin)
            maxSize_++;
         else if (htab_.size() >= maxSize_)
            this->purgeOld();
         htab_.emplace(k, Data(d, pin));
         return true;
      }
   }

   bool insertWithCount(KeyType k, const DataType& d, CounterType initVal, 
                        long clock_us, bool update=false) {
      if (initVal == 0) initVal = 1;
#ifdef MFU_DBG
      insct++;
#endif
      auto it = htab_.find(k);
      if (it != htab_.end()) {
         updateAcc(1, 0, clock_us);
         it->second.__count(initVal);
         if (update)
            it->second.data(d);
         return false;
      }
      else {
         updateAcc(1, 1, clock_us);
         if (htab_.size() >= maxSize_)
            this->purgeOld();
         htab_.emplace(k, Data(d, initVal));
         return true;
      }
   }

   // Explicit removes are not considered "accesses" for the purpose of 
   // calculating hitRate(). Because they are expicitly done, we don't 

   Data remove(KeyType k, bool force=false) {
      // All entries in table will have count > 0, so rv.count==0 means the
      // key was not found or removed. 
      // To remove pinned entries, call with force=true.
      Data rv;
      auto it = htab_.find(k);
      if (it != htab_.end()) {
         if (!it->second.pinned() || force) {
            rv = it->second;
            if (it->second.pinned()) maxSize_--;
            htab_.erase(k);
         }
      }
      return rv;
   }

   void clear() { removeAll(); };

   void removeAll() {
      if (ownsPtr_)
         removeAndDestroyAll();
      else htab_.clear();
   }

   void removeAndDestroyAll() {
      if constexpr (is_pointer<DataType>::value)
         for (auto i = htab_.begin(); i != htab_.end(); i++)
            delete i->second.data();
      htab_.clear();
   }

   void print(ostream& os) const {
      os << " maxCount: " << maxCount_
         << " size: " << maxSize_ << endl;
      ::print(htab_, os);
   }

 private:

   void halveCount() { // Divide all counts by 2
      unsigned rv=0;
      misses_ = (misses_+1) >> 1;
      accesses_ = (accesses_+1) >> 1;
      for (auto& elem: htab_) {
         long nv = elem.second.count();
         unsigned nnv = (nv+1) >> 1;
         rv = max(rv, nnv);
         elem.second.__count(nnv);
      }
      maxCount_ = rv;
   }

   static inline unsigned 
   scale(unsigned x, unsigned mulfac) {
      return (((unsigned long)x) * mulfac + (1ul<<31)) >> 32;
   }

   void updateAcc(unsigned acc, unsigned miss, long clock_us) {

#ifdef DECAY_MFU
      if (clock_us - lastDecay_us_ > (((long)decayGen_)<<tsshift_)) {
         // @@@@ Assumes decayTime_ is long enough and calls to this function
         // @@@@ frequent enough that there is no need to loop here. 
         lastDecay_us_ = clock_us;
         unsigned rv = 0;
         accesses_ = scale(accesses_, decayFac_);
         misses_ = scale(misses_, decayFac_);
         for (auto& elem: htab_) {
            elem.second.__count(scale(elem.second.count(), decayFac_));
            rv = max(rv, (unsigned)elem.second.count());
         }
         maxCount_ = rv;
      }
#endif

      if (accesses_ >= UINT_MAX - acc)
         halveCount();
      misses_ += miss;
      accesses_ += acc;
   }

   // @@@@ It may be much faster if we destroy the entire hash table and
   // @@@@ rebuild a new table of the right size. This will avoid repeated
   // @@@@ rehashing that happens when table is shrunk gradually. But we
   // @@@@ should test this before making the change.

   void purgeOld() {
      unsigned npinned = 0;
#ifdef MFU_DBG
      if (dbg) { cout << "purgeOld called\n"; print(cout);}
#endif
      for (auto it = htab_.begin(); it != htab_.end();) {
         if (it->second.pinned())
            npinned++;
         else if (it->second.count() == 0) {
            // assert_abort(0); // Should never be the case!
            if (shrink)
               shrink(it->first, it->second, true);
            it = htab_.erase(it);
            continue;
         }
         it++;
      }

      unsigned unpinned = htab_.size() - npinned;
      unsigned targetMax = (maxSize_ -  npinned)*0.55; // maxSize_ >= 8 ==>
      unsigned targetMin = (maxSize_ -  npinned)*0.45; //   targetMax > targetMin

      // assert_abort(unpinned >= targetMax);
      if (unpinned >= targetMax) { 
         unsigned n = unpinned + 2; // +2 to hold sentinel entries
         // We use key pointers as we can fit pointer and count in 8 bytes.
         // Unless keys are 2 bytes or less, MFUData<KeyType> won't be smaller.
         // Note: there is no performance hit in using pointers, as they
         // are not dereferenced in the loop below.
         MFUData<const KeyType*> *key = new MFUData<const KeyType*> [n];
         key[0].__count(0); 
         key[n-1].__count(Data::maxCount()); // sentinel value
         unsigned l = 1;
         for (auto& elem: htab_) {
            if (!elem.second.pinned()) {
               key[l].__count(elem.second.count());
               key[l].data(&elem.first);
               l++;
            }
         }
         assert_abort(l==n-1);

         unsigned const minRemoved = n - targetMax - 1;
         unsigned const maxRemoved = n - targetMin - 1; 
         unsigned first = 1, last = n-2; 

         /*** Invariant: last >= maxRemoved > minRemoved > first,
              key[0..first) <= key[first, n)                         ***/

         while (first < minRemoved) { 
            /*** Invariant: last >= maxRemoved > minRemoved > first 
                 key[0..first) <= key[first, n)                      ***/
            unsigned pivot = first + random() % (last-first);
            swap(key[pivot], key[first]);
            unsigned pivotCount = key[first].count();
            unsigned i = first; unsigned j = last+1;
            do {
               /* Invariants: first <= i < j <= last+1,
                    key[0..first) <= key[first..i] <= pivotCount <= key[j..n)*/

               while  (key[++i].count() < pivotCount);
               /*** Invariants: 
                  first <= i-1 < i <= j <= last+1,
                  key[0..first) <= key[first..i-1] <= pivotCount <= key[j..n),
                  pivotCount <= key[i]
                ****************************************************************
                * One could change either the i and j loops go past elements
                * equal to pivotCount. But the current Hoare partitioning scheme
                * is advantageous: if there are many elements equal to
                * pivotCount, then they get distributed equally across the two
                * partitions. Otherwise, such elements will cause the partition
                * to skew to one side, raising the possibility of the worst case
                * quadratic behavior.
                *
                * Additionally, this partitioning scheme avoids the need for
                * bounds checks on i and j. 
                ***************************************************************/

               while  (key[--j].count() > pivotCount);
               /*** Invariants: 
                 first <= i-1 <= j <= last,
                 key[0..first) <= key[first..i-1] <= pivotCount <= key[j+1..n),
                 key[j] <= pivotCount <= key[i]  ***/

               if (i >= j) /* j must be i or i-1 */ 
                  break;

               swap(key[i], key[j]);
               /*** Invariants: 
                  first <= i < j <= last,
                  key[0..first) <= key[first..i] <= pivotCount <= key[j..n) */
            } while (1);

            swap(key[first], key[j]);
            /*** Inv: first <= i-1 <= j <= last, key[0..first) <= key[first..n),
                 j=i-1 ==> key[first..j] <= pivotCount <= key[j+1..n)
                 j=i   ==> key[first..j] <= pivotCount <= key[j+1..n)
              SO: key[0..first) <= key[first..j] <= pivotCount <= key[j+1..n) */

            if (maxRemoved <= j)
               last = j;
            else first = j+1; /**** Inv: key[0..first) <= key[first..n) ****/
         }
         /**********************************************************************
          * minRemoved <= first <= maxRemoved+1, key[0..first) <= key[first..n)
          *  
          * This means key[0..first) can be purged, they will all be less than
          * or equal to the retained keys, and that size of remaining array
          * will be within the range of targetMin to targetMax.           
          *********************************************************************/

         for (unsigned k=1; k < first; k++) {
            auto ky = *key[k].data();
            Data d = remove(ky);
            if (shrink)
               shrink(ky, d, true);
         }

         delete [] key;
      }

#ifndef DECAY_MFU
// Instead of calling adjCount(), it is best to reset all counts to 1,
      for (auto& elem: htab_)
        elem.second.__count(1);
#else
// If we change counts here, that will mess up the decaying count semantics. So,
// we leave the counts as is; just purge the ones that need to be purged.
#endif

#ifdef MFU_DBG
      if (dbg) { cout << "purgeOld returning\n"; print(cout); }
#endif
   }
};
#undef updateAcc
#undef lookup
#undef lookupData
#undef update
#undef insert
#undef insertWithCount

#define Base BaseMFUTable<KeyType, MFUVoid, CounterType>

template<class KeyType, class CounterType=unsigned>
class BaseMFUSet: public Base {
 public:
   typedef std::function<void(KeyType, MFUData<MFUVoid, CounterType>, bool beingRemoved)> ShrinkFnType;

   BaseMFUSet(): Base() {};

#ifndef DECAY_MFU
   BaseMFUSet(unsigned maxSize, ShrinkFnType sf={}):
       Base(maxSize, sf) {};
   BaseMFUSet(unsigned maxSz, int takeOwnershipOfPtrData): 
       Base(maxSz, takeOwnershipOfPtrData) {};

   bool contains(KeyType k) { return (Base::lookup(k)); }
   long lookup(KeyType k) { 
      long rv = -1;
      const auto *d = Base::lookup(k);
      if (d) rv = d->count();
      return rv;
   }

   bool insert(KeyType k, bool pin=false) {
      return Base::insert(k, MFUVoid(), pin);
   }

   bool insertWithCount(KeyType k, CounterType initval) {
      return Base::insertWithCount(k, MFUVoid(), initval);
   }

   long remove(KeyType k, bool force=false) 
      { return Base::remove(k, force).second; }

#else
   BaseMFUSet(unsigned maxsz, double decayFac, long decayGen_us, 
            long clock_us, ShrinkFnType sf={}):
      Base(maxsz, decayFac, decayGen_us, clock_us, sf) {};

   BaseMFUSet(unsigned maxSz, int takeOwnershipOfPtrData, double decayFac, 
       long decayGen_us, long clock_us): 
      Base(maxSz, takeOwnershipOfPtrData, decayFac, decayGen_us, clock_us) {};

   bool contains(KeyType k, long clock_ts) 
      { return (Base::lookup(k, clock_ts)); }
   long lookup(KeyType k, long clock_ts) { 
      long rv = -1;
      const auto *d = Base::lookup(k, clock_ts);
      if (d) rv = d->count();
      return rv;
   }

   bool insert(KeyType k, long clock_ts, bool pin=false) {
      return Base::insert(k, MFUVoid(), clock_ts, pin);
   }

   bool insertWithCount(KeyType k, CounterType initval, long clock_ts) {
      return Base::insertWithCount(k, MFUVoid(), initval, clock_ts);
   }

   long remove(KeyType k, long clock_ts, bool force=false) 
      { return Base::remove(k, clock_ts, force).second; }

#endif

   void visitAll(std::function<void(KeyType, CounterType)> f) {
      for (auto e: this->htab()) {
#ifdef MFU_DBG
         nvisit++;
#endif
         f(e.first, e.second.count());
      }
   }

   void visitAll(std::function<void(const KeyType&, const CounterType&)> f) const {
      for (auto e: this->htab()) {
#ifdef MFU_DBG
         nvisit++;
#endif
         f(e.first, e.second.count());
      }
   }
};

#undef Base
#undef contains
#undef insert
#undef insertWithCount
