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

#ifndef BASE_H
#define BASE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <algorithm>
#include <climits>

extern int logLevel;

#define DEBUGLEVEL 5
#define INFOLEVEL  4
#define WARNLEVEL  3
#define ERRLEVEL   2

#define errMsg(x) do { if (logLevel >= ERRLEVEL) { x; }} while(0)
#define warnMsg(x) do { if (logLevel >= WARNLEVEL) { x; }} while(0)
#define infoMsg(x) do { if (logLevel >= INFOLEVEL) { x; }} while(0) 
#define dbgMsg(x) do { if (logLevel >= DEBUGLEVEL) { x; }} while(0) 
#define errPrtf(...)  \
   do { if (logLevel >= ERRLEVEL)   fprintf(stderr, __VA_ARGS__);} while(0)
#define warnPrtf(...) \
   do { if (logLevel >= WARNLEVEL)  fprintf(stderr, __VA_ARGS__);} while(0)
#define infoPrtf(...) \
   do { if (logLevel >= INFOLEVEL)  fprintf(stderr, __VA_ARGS__);} while(0)
#define dbgPrtf(...)  \
   do { if (logLevel >= DEBUGLEVEL) fprintf(stderr, __VA_ARGS__);} while(0)

#ifdef TESTING
#define assert_try(x) assert(x)
#define assert_fix(x, y) assert(x)
#define assert_abort(x) assert(x)
#else
#undef assert
#define assert(x) static_assert(0==1, "Assert disabled, use assert_fix, assert_abort, or other variants");
#define assert_try(cond) do {\
   if (!(cond)) \
      errMsg(std::cerr << "***** " << __FILE__ << ":" << __LINE__ << \
             ": Assertion " << #cond << " violated, attempting to continue\n");\
} while (0)

#define assert_fix(cond, fix) do {\
   if (!(cond)) {\
      errMsg(std::cerr << "***** " << __FILE__ << ":" << __LINE__ \
             << ": Assertion " << #cond << " violated, correcting action: " \
             << #fix << '\n'); \
      do { fix; } while (0); \
   }\
} while (0)

#define assert_abort(expr) \
   ((expr)                                      \
   ? __ASSERT_VOID_CAST (0)						\
   : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))
#endif

#define getbf(x, n) (x & (1ul<<(n)))
#define setbf(x, n, i) x = ((x) & (~(1ul<<(n)))) | ((i) << (n))
#define getbfs(x, n, m) (((x) & ((m)<<(n))) >> (n))
#define setbfs(x, n, i, m) x = (x & (~((m)<<(n))))|((i&m)<<(n))
#define mask(n) ((1ul<<(n))-1)

inline constexpr unsigned nbits(unsigned l) { 
   return 32 - (l > 0? __builtin_clz(l) : 32); 
};
inline constexpr unsigned nbits(unsigned long l) { 
   return 64 - (l > 0? __builtin_clzl(l) : 64);
};

inline constexpr int ilog2(unsigned l) { 
   return (l > 0? 31 - __builtin_clz(l) : INT_MIN); 
};
inline constexpr int ilog2(unsigned long l) { 
   return (l > 0? 63 - __builtin_clzl(l) : INT_MIN);
};

#define cmax(x,y) (((x) >= (y))? (x) : (y))

using namespace std;
#endif
