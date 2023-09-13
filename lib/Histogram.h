/*******************************************************************************
 *  Copyright 2022-23 R. Sekar and Secure Systems Lab, Stony Brook University
 *******************************************************************************
 * This file is part of eAudit.
 *
 * eAudit is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * eAudit is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * eAudit. If not, see <https://www.gnu.org/licenses/>.
 ******************************************************************************/

#ifndef HISTOGRAM_H
#define HISTOGRAM_H

using namespace std;

#include <stdio.h>
#include <math.h>
#include "Base.h"

/*******************************************************************************
* Histograms take the following template parameters: 
*
*   -- N: the number of bins. 
*
*   -- ElemType: a numeric type that denotes the type of elements in the 
*      Histogram. It affects neither the size nor the performance of Histograms
*      so it is best to use long, uint64_t, or double.
*
*   -- BinType: The representation of each bin. Storage-wise, Histograms are 
*      just an array[N] of BinType. Best to leave BinType to be the default
*      choice. However, if no precision loss is tolerable, BinType should be
*      specified as uint64_t; or, if counts can go beyond 2^64, specify BinType
*      as double.
*
*   -- Binner: a class that specifies how elements are grouped into bins. It 
*      should provide two static functions:
*        -- bin(ElemType) -> unsigned that mapping a value to a bin number, and
*        -- start(unsigned i) -> ElemType that gives the smallest value in bin i.
*      Specifically:
*        -- bin i holds values v such that binstart(i) <= v < binstart(i-1)
*      So the following invariant should hold for these two functions:
*        -- binstart(bin(n)) <= n < binstart(bin(n)+1)
*      We can't track the high end of the last bin, so everything greater than
*      or equal to binstart(N-1) will go there. 
*
* This Histogram class is very flexible but needs significant work to set up. In
* particular, we need to define a Binner class. This is done in HistoBinner.h.
* Several easy-to-setup histogram types are also defined in that header file.
*******************************************************************************/

template <class Binner, class ElemTp, class BinType>
class Histogram {
   typedef Histogram<Binner, ElemTp, BinType> Self;
 private:
   BinType bin_[Binner::nbins()];

 public:
   typedef ElemTp ElemType;

   Histogram() { if constexpr (is_arithmetic_v<BinType>) clear(); };
   Histogram(const Histogram& other) { *this = other;};

   const Histogram& operator=(const Histogram& other) {
      for (unsigned i=0; i < Binner::nbins(); i++) 
         bin_[i] = other.bin_[i];
      return *this;
   }
   bool operator==(const Histogram& other) const {
      for (unsigned i=0; i < Binner::nbins(); i++) 
         if (bin_[i] != other.bin_[i]) return false;
      return true;
   }
   bool operator!=(const Histogram& other) const {return !(operator==(other));}

   void clear() { for (unsigned i=0; i < Binner::nbins(); i++) bin_[i] = 0; }

   uint64_t npoints() const;

   void addPoint(ElemTp p) { ++bin_[Binner::bin(p)]; };
   void addPoint(ElemTp p, unsigned ct) { bin_[Binner::bin(p)] += ct; }
   void rmPoint(ElemTp p, unsigned ct) { bin_[Binner::bin(p)] -= ct; }

   void addToBinZero(uint64_t count) { bin_[0] += count;};

   void merge(const Self& other); // Computes the union of the two histograms

   void print(std::ostream& os, bool cumulative=false, 
              bool normalize=true) const {
      double sum=0; unsigned maxnzbin=0, minnzbin=1<<30;

      double npts=0;
      for (unsigned i=0; i < Binner::nbins(); i++) {
         if (bin_[i] != 0) {
            maxnzbin=i;
            if (i < minnzbin)
               minnzbin = i;
            npts += (double)bin_[i];
         }
      }

      for (unsigned i=0; i <= maxnzbin; i++) {
         double binval = Binner::start(i);
         if (i < Binner::nbins()-1)
            binval = (binval+Binner::start(i+1))/2;
         sum += binval * (double)bin_[i];
      }

      os << "Range: " << Binner::start(minnzbin) << " to " << Binner::start(maxnzbin+1);
      /*if (maxnzbin < Binner::nbins()-1)
        os << Binner::start(maxnzbin+1)-1;
        else os << "over " << Binner::start(maxnzbin);*/
      os << "   N: " << npts << " Mean: " << (1e-50+sum)/(1e-50+npts) << std::endl;

      double c = 0; 
      if (minnzbin == maxnzbin) return;
      // If only one of the bins is non-empty, this can be figured out from
      // the info already printed, so  we skip printing the bins. Otherwise
      // we print the subset of bins, startning from minimum bin that is nonzero.
      
      for (unsigned i=minnzbin; i <= maxnzbin; i++) {
      c = cumulative ? c + (double)bin_[i] : (double)bin_[i];
      double p = normalize? c/npts : c;
      os << p << ' ';
      }
      os << std::endl; 
   }

   void print(FILE *fp, bool cumulative=false, 
              bool normalize=true) const;

   void serialize(FILE *fp) const {
      unsigned mxbin=0;
      for (unsigned i=0; i < Binner::nbins(); i++)
         if (bin_[i] != 0) 
            mxbin = i+1;
      fprintf(fp, "%d ", mxbin);
      for (unsigned i=0; i < mxbin; i++)
         fprintf(fp, "%lu ", (uint64_t)bin_[i]);
      fputc('\n', fp);
   }

   void deserialize(FILE* fp) {
      uint64_t l; unsigned mxbin;
      assert_abort(fscanf(fp, "%d", &mxbin)==1);      
      for (unsigned i=0; i < mxbin; i++) {
         assert_abort(fscanf(fp, "%lu", &l)==1);
         bin_[i] = l;
      }
      for (unsigned i=mxbin; i < Binner::nbins(); i++)
         bin_[i] = 0;
   }
};

template<unsigned n2bins=64, unsigned n4bins=0, unsigned n8bins=0, 
         unsigned n16bins=0>
struct Geo24816Binner {
   static constexpr unsigned nbins() { return 1+n2bins+n4bins+n8bins+n16bins;};
   static constexpr unsigned bin(uint64_t v) {
      if (v < 2) return v;
      unsigned logv = ilog2(v); 
      unsigned rv = logv;
      if (rv < n2bins) 
         return 1+logv; // 2 <= v < 2^n2b, rv=log2(v)+1
      rv = (logv-n2bins)/2; 
      if (rv < n4bins) // log2(v) < n2b+2n4b
         return 1+n2bins+rv; // 2^n2b <= v < 2^(n2b+2*n4b)
      rv = (logv-n2bins-2*n4bins)/3;
      if (rv < n8bins) // log2(v) < logv+n2b+2n4b+3n8b
         return 1+n2bins+n4bins+rv;
      rv = (logv-n2bins-2*n4bins-3*n8bins)/4;
      if (rv < n16bins) // log2(v) < logv+n2b+2n4b+3n8b+4n16b
         return 1+n2bins+n4bins+n8bins+rv;
      return nbins()-1;
   };
   // Example to check: 0-0 1-1 2-3 4-7 8-31 32-127 128-2047 2048-32767
   // Zero bin is not counted, so n2bins=3, n4bins=2, n8bins=0, n16bins=2
   static constexpr uint64_t start(unsigned i) {
      uint64_t rv=0;
      if (i > 0) {
         rv=1;
         i--;
         if (i < n2bins)
            rv <<= i;
         else {
            rv <<= n2bins;
            i -= n2bins;
            if (i < n4bins)
               rv <<= 2*i;
            else {
               rv <<= 2*n4bins;
               i -= n4bins;
               if (i < n8bins)
                  rv <<= 3*i;
               else {
                  rv <<= 3*n8bins;
                  i -= n8bins;
                  if (i < n16bins)
                     rv <<= 4*i;
                  else rv <<= 4*n16bins;
               }
            }
         }
      }
      return rv;  
   };
};

using LongHistogram = Histogram<Geo24816Binner<63,0,0,0>,uint64_t,uint64_t>;

template <class Binner, class ElemTp, class BinTp>
ostream& operator<<(ostream& os, const Histogram<Binner, ElemTp, BinTp>& h) {
   h.print(os); return os;
};

#endif
