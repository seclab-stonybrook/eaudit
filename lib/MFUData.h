#ifndef MFU_DATA
#define MFU_DATA
template<class DataType, class CounterType=unsigned short> 
class MFUData {
 private:
   DataType data_;
   CounterType pinned_: 1;
   CounterType count_: sizeof(CounterType)*8-1;

 public:
   MFUData(): data_(), pinned_(0), count_(0){};

   MFUData(DataType d, bool pin=false): data_(d) {
      count_ = 1; 
      pinned_ = pin;
   };

   MFUData(DataType d, CounterType c): data_(d) {
      count_ = c; 
      pinned_ = false;
   };

   static unsigned long maxCount() { return (1ul<<(sizeof(CounterType)*8-1))-1;};

   bool pinned() const { return pinned_; };
   CounterType count() const { return count_; };
   void __count(CounterType c) { // DON'T USE: only for use by MFUTable/Set
      count_ = c; 
   }; 
   DataType data() const { return data_; };
   void data(DataType d) { data_ = d; };

   void print(ostream& os) const { 
      os << '(' << count_ << ", " << data_ << ')';
      if (pinned_) os << 'p';
   }
};

template<class DataType, class CounterType> 
ostream& operator<<(ostream& os, const MFUData<DataType, CounterType>& d) {
   d.print(os); return os;
};

template<class DataType> 
class MFUData<DataType*, unsigned short> {
   bool pinned_: 1;
   unsigned short count_: 15;
   unsigned long data_: 48;

   static const unsigned long maxd =  ((1ul<<48)-1);
   static const unsigned long maxb =  (1ul<<47);
   static const unsigned long ptrmask = 0xfffful << 48;
   typedef MFUData<DataType*, unsigned short> Self;

 public:
   MFUData(): pinned_(0), count_(0) { data(nullptr); };

   MFUData(DataType* d, bool pin=false) {
      count_ = 1; 
      pinned_ = pin;
      data(d);
   };

   MFUData(DataType* d, unsigned short c) {
      count_ = c; 
      pinned_ = false;
      data(d);
   };

   static unsigned long maxCount() { return (1ul<<(15))-1;};

   bool pinned() const { return pinned_; };
   unsigned short count() const { return count_; };
   void __count(unsigned short c) { // DON'T USE: only for use by MFUTable/Set
      count_ = c; 
   }; 

   DataType* data() {
      unsigned long mask = (data_ & maxb) ? ptrmask : 0;
      return (DataType*)(data_ | mask);
   }

   const DataType* data() const { return const_cast<Self*>(this)->data(); };
   void data(DataType* d) { data_ = ((unsigned long)d) & maxd; }

   void print(ostream& os) const { 
      os << count_ << (pinned_? "P: " : ": ") << data();
   }
};

class MFUVoid {
 private:
#ifdef __llvm__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-private-field"
   char discardPlaceHolder_;
#pragma GCC diagnostic pop
#endif
 public:
   MFUVoid() {};
};

template<class CounterType> 
class MFUData<MFUVoid, CounterType> {
   CounterType pinned_: 1;
   CounterType count_: sizeof(CounterType)*8-1;

 public:
   MFUData(): pinned_(0), count_(0) {}

   MFUData(MFUVoid v, bool pinned=false): 
      pinned_(pinned), count_(1) {};

   MFUData(MFUVoid v, CounterType c) {
      count_ = c; 
      pinned_ = false;
   };

   MFUData(CounterType c, bool pin=false) {
      count_ = c; 
      pinned_ = pin;
   };

   static unsigned long maxCount() { return (1ul<<(sizeof(CounterType)*8-1))-1;};

   bool pinned() const { return pinned_; };
   CounterType count() const { return count_; };
   void __count(CounterType c) { // DON'T USE: only for use by MFUTable/Set
      count_ = c; 
   }; 

   MFUVoid data() const { return MFUVoid(); };
   void data(MFUVoid d) {};

   void print(ostream& os) const { 
      os << count_;
      if (pinned_) os << 'p';
   }
};

template<class CounterType> 
using MFUSetData = MFUData<MFUVoid, CounterType>;

#endif
