#ifndef STL_UTILS_H
#define STL_UTILS_H

#include <algorithm>
#include <tuple>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>
#include <list>
#include <map>
#include <iostream>
#include <sstream>

#include <limits.h>
#include "FastHash.h"
#include "Base.h"

using namespace std;

template <class T>
void sort_unique(vector<T> l) {
   sort(l.begin(), l.end());
   l.erase(unique(l.begin(), l.end()), l.end());
}

template <class T>
void print(const vector<T>& t, ostream& os, char ldelim='[', char rdelim=']',
           const char* sep=", ") {
   os << ldelim; bool b = false;
   for (const T& e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class T>
void print(const unordered_set<T>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* sep=", ") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class T>
void print(const set<T>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* sep=", ") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << sep;
      else b = true;
      os << e;
   }
   os << rdelim;
}

template <class K, class V>
void print(const unordered_map<K, V>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* itemsep=", ", const char*keysep=":") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << itemsep;
      else b = true;
      os << e.first << keysep << e.second;
   }
   os << rdelim;
}

template <class K, class V>
void print(const map<K, V>& t, ostream& os, char ldelim='{', 
           char rdelim='}', const char* itemsep=", ", const char*keysep=":") {
   os << ldelim; bool b = false;
   for (auto e: t) {
      if (b) os << itemsep;
      else b = true;
      os << e.first << keysep << e.second;
   }
   os << rdelim;
}

template<class T1, class T2>
void print(const pair<T1, T2>& tp, ostream& os, 
           char ldelim='(', char rdelim=')', const char* sep=", ") {
   os << ldelim << tp.first << sep << tp.second << rdelim;
}

template<class Tuple, std::size_t N>
struct TuplePrinter {
    static void print(const Tuple& t, ostream& os, const char* sep=", ") {
        TuplePrinter<Tuple, N-1>::print(t, sep);
        os << ", " << std::get<N-1>(t);
    }
};
 
template<class Tuple>
struct TuplePrinter<Tuple, 1> {
    static void print(const Tuple& t, ostream& os, const char* sep=", ") {
        os << std::get<0>(t);
    }
};

template<class... Args>
void print(const std::tuple<Args...>& t, ostream& os, 
           char ldelim='(', char rdelim=')', const char* sep=", ") {
    os << ldelim;
    TuplePrinter<decltype(t), sizeof...(Args)>::print(t, os, sep);
    os << rdelim;
};

template <class T>
ostream& operator<<(ostream& os, const vector<T>& t) { print(t, os); return os;};
template <class T>
ostream& operator<<(ostream& os, const set<T>& t) { print(t, os); return os;};
template <class T>
ostream& operator<<(ostream& os, const unordered_set<T>& t) 
  { print(t, os); return os;};
template <class K, class T>
ostream& operator<<(ostream& os, const unordered_map<K, T>& t) 
  { print(t, os); return os;};
template<class... Args>
ostream& operator<<(ostream& os, const tuple<Args...>& t) 
  { print(t, os); return os;};

namespace std {
    namespace
    {

        /* I am unconvinced by this combination function. Golden ratio
           it seems!

        // Code from boost
        // Reciprocal of the golden ratio helps spread entropy
        //     and handles duplicates.
        // See Mike Seymour in magic-numbers-in-boosthash-combine:
        //     http://stackoverflow.com/questions/4948780

        template <class T>
        inline void hash_combine(std::size_t& seed, T const& v)
        {
            seed ^= std::hash<T>()(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }
        */

        // When used in a typical fashion, e.g., on a vector [an,...,a0],
        // yields sum_{i=0}{n} a_i x^i
        template <class T>
        inline void hash_combine_asymm(std::size_t& seed, T const& v) {
            constexpr size_t x = 7892540079625801679ul; // some random odd?
            size_t vh = std::hash<T>()(v);
            seed += x*seed + vh;
        }

        // Hash combo for unordered collections [an,...,a0]. The result is
        // prod_{i|odd(a_i)} (a_i + x) * prod_{j|even(a_j)} ~(a_j+x)

        template <class T>
        inline void hash_combine_symm(std::size_t& seed, T const& v) {
           assert_abort(seed != 0);
            constexpr size_t x = 7277111512771247327ul; // some random odd
            size_t vh = x + std::hash<T>()(v);
            if (!(vh&0x1))
               vh = ~vh;
            seed *= vh;
        }

        // Recursive template code derived from Matthieu M.
        template <class Tuple, size_t Index = std::tuple_size<Tuple>::value - 1>
        struct HashValueImpl
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            HashValueImpl<Tuple, Index-1>::apply(seed, tuple);
            hash_combine_asymm(seed, std::get<Index>(tuple));
          }
        };

        template <class Tuple>
        struct HashValueImpl<Tuple,0>
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            hash_combine_asymm(seed, std::get<0>(tuple));
          }
        };
    }

    template <typename ... TT>
    struct hash<std::tuple<TT...>> 
    {
        size_t
        operator()(std::tuple<TT...> const& tt) const
        {                                              
            size_t seed = 0;                             
            HashValueImpl<std::tuple<TT...> >::apply(seed, tt);    
            return seed;                                 
        }                                              

    };

   template <class T> 
   struct hash<vector<T>> {
   public:
      size_t operator()(const vector<T>& t) const {
         size_t tc[t.size()]; unsigned j=0;
         for (const T& v: t) 
            tc[j++] = std::hash<T>()(v);
         return fasthash64(&tc[0], t.size()*sizeof(size_t), t.size());
      }
   };

   template <class T> 
   struct hash<set<T>> {
   public:
      size_t operator()(const set<T>& t) const {
         size_t tc[t.size()]; unsigned j=0;
         for (const T& v: t)
            tc[j++] = std::hash<T>()(v);
         return fasthash64(&tc[0], t.size()*sizeof(size_t), t.size());
      }
   };

   template <class T1, class T2> 
   struct hash<pair<T1, T2>> {
   public:
      size_t operator()(const pair<T1, T2>& t) const {
         size_t rv = hash<T1>()(t.first);
         hash_combine_asymm(rv, t.second);
         return rv;
      }
   };

   template <class T1, class T2> 
   struct hash<unordered_map<T1, T2>> {
   public:
      size_t operator()(const unordered_map<T1, T2>& t) const {
         size_t rv = t.size()+1; // shd be nonzero now
         for (auto& kv: t) {
            size_t kvh = hash<T1>()(kv.first);
            hash_combine_asymm(kvh, hash<T2>()(kv.second));
            hash_combine_symm(rv, kvh);
         }
         return rv;
      }
   };

   template <class T> 
   struct hash<unordered_set<T>> {
   public:
      size_t operator()(const unordered_set<T>& t) const {
         size_t rv = t.size()+1;
         for (auto& s: t)
            hash_combine_symm(rv, hash<T>()(s));
         return rv;
      }
   };

   template <> struct hash<const char*> {
     public :
      size_t operator()(const char* u) const { return fasthash64(u); }
   };

   template <> class equal_to<const char*> {
     public:
      size_t operator()(const char* s1, const char *s2) const
      { return (strcmp(s1,s2) == 0);  }
   };

};

template <class C>
class IndexAsg  {
   unsigned count_;
   string prefix_;
   unordered_map<C, unsigned> dict_;

 public:
   void setPrefix(string p) { prefix_=p; };
   string getPrefix() const { return prefix_;}

   void clear() { 
      dict_.clear(); 
      count_ = 0; 
   };

   unsigned getIndex(const C& nm, bool& isNew) {
      if (dict_.find(nm) != dict_.end()) {
         isNew = false;
         return dict_[nm];
      }
      else {
         isNew = true;
         dict_[nm] = count_;
         return count_++;
      }
   };

   unsigned getIndex(const C& nm) {
      bool isNew;
      return getIndex(nm, isNew);
   };

   string getName(C nm, bool& isNew) {
      unsigned idx = getIndex(nm, isNew);
      return prefix_ + to_string(idx);
   }
};


template <class C> void
serialize(ostream& os, const C& c) {
   c.serialize(os);
}

template <> inline void
serialize<const char*>(ostream& os, const char* const& s) {
   uint64_t l = strlen(s);
   os << l << ' ';
   os.write(s, l);
   //os << endl;
}

template <class C> void
deserialize(istream& is, C& c) {
   new (&c) C(is);
}

template <> inline void
deserialize<const char *>(istream& is, const char*& s) {
   uint64_t l; char c;
   is >> l;
   is.read(&c, 1);
   assert_try(c == ' ');
   char *ss = new char[l+1];
   is.read(ss, l);
   ss[l] = '\0';
   s = ss;
   //is.ignore(1);
}

template <class C> void
serializevs(const vector<C>& v, ostream& os) {
   os << v.size() << endl;
   for (uint64_t i=0; i < v.size(); i++) {
      v[i].serialize(os);
      os << endl;
   }
}

template <class C> void
deserializevs(istream& is, vector<C>& v) {
   uint64_t n;
   is >> n;
   for (uint64_t i=0; i < n; i++) {
      char t;
      is.read(&t, 1);
      assert_try(t == '\n');
      if (i >= v.size())
         v.emplace_back(is);
      else {
         C* e = &v[i];
         new (e) C(is);
      }
   }
   is.ignore(1);
}

inline string 
sanitize(const char* in, const char* escape="", int min=' ', int max='~') {
   string rv;
   int c;
   auto tohex = [](int i) {
                    if (i >= 0 && i < 10) return (char)('0'+i);
                    else if (i >= 10 && i < 16) return (char)('a'+(i-10));
                    else return ' ';
   };
   while ((c=*in++)) {
      if (c < min || c > max) {
         rv.push_back('\\');
         rv.push_back('x');
         rv.push_back(tohex((c>>4)&0xf));
         rv.push_back(tohex(c & 0xf));
      }
      else {
         if (strchr(escape, c))
            rv.push_back('\\');
         rv.push_back(c);
      }
   }
   return rv;
}

inline string 
sanitize(string in, const char* escape="", int min=' ', int max='~') {
   return sanitize(in.data(), escape, min, max);
}

// This returns in the same fashion as <=>: negative means a < b, positive means a > b, zero means a == b
// We compare first by size, ensuring that our ordering is a linear extension of the subset relation
template<class T>
int cmp_set(const unordered_set<T>& a, const unordered_set<T>& b) {
    if (a.size() - b.size()) return a.size() - b.size();
    vector<T> vec_a(a.begin(), a.end()), vec_b(b.begin(), b.end());
    // pop and compare minimums
    make_heap(vec_a.begin(), vec_a.end(), greater<T>());
    make_heap(vec_b.begin(), vec_b.end(), greater<T>());
    auto heap_end_a = vec_a.end(), heap_end_b = vec_b.end();
    for (unsigned ct = 0; ct < a.size(); ct++) {
        if (*vec_a.begin() > *vec_b.begin()) return +1;
        else if (*vec_a.begin() < *vec_b.begin()) return -1;
        pop_heap(vec_a.begin(), heap_end_a--, greater<T>());
        pop_heap(vec_b.begin(), heap_end_b--, greater<T>());
    }
    return 0;
}

template<class K, class V>
int cmp_dict(const unordered_map<K, V>& a, const unordered_map<K, V>& b) {
    if (a.size() - b.size()) return a.size() - b.size();
    vector<K> vec_a, vec_b;
    for (auto it = a.begin(); it != a.end(); ++it)
        vec_a.push_back(it->first);
    for (auto it = b.begin(); it != b.end(); ++it)
        vec_b.push_back(it->first);
    // pop and compare minimum keys (same code as above)
    make_heap(vec_a.begin(), vec_a.end(), greater<K>());
    make_heap(vec_b.begin(), vec_b.end(), greater<K>());
    auto heap_end_a = vec_a.end(), heap_end_b = vec_b.end();
    for (unsigned ct = 0; ct < a.size(); ct++) {
        if (*vec_a.begin() > *vec_b.begin()) return +1;
        else if (*vec_a.begin() < *vec_b.begin()) return -1;
        pop_heap(vec_a.begin(), heap_end_a--, greater<K>());
        pop_heap(vec_b.begin(), heap_end_b--, greater<K>());
    }
    // compare by values (vec_a and vec_b are now sorted in descending order, so we iterate in reverse)
    auto i = vec_a.rbegin(); auto j = vec_b.rbegin();
    for (unsigned ct = 0; ct < a.size(); ct++) {
        if (a.at(*i) > b.at(*j)) return +1;
        else if (a.at(*i) < b.at(*j)) return -1;
        ++i; ++j;
    }
    return 0;
}

#endif
