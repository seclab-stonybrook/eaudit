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

#include <iostream>
#include <string>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <vector>
#include <stdio.h>
#include <time.h>
#include <cstring>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include <cassert>
#include <sys/types.h>
#include <grp.h>

#include "eauditd.h"
#include "eauditk.h"

#ifndef CAPTURE_ONLY
#include "eParser.h"
#endif

using namespace std;

int capture_fd=-1;
enum CaptureState {NOT_ENABLED, OPEN, CLOSED};
CaptureState cap_state;
static size_t nbytes, ncalls, numwritten;
static bool parser_on;
size_t nwrites;

void exitError(const char* msg) {
   fprintf(stderr, "%s\n", msg);
   exit(1);
}

void errExit(const char* msg, const char* buf=nullptr, size_t len=0) {
   if (!buf)
      perror(msg);
   else {
      fprintf(stderr, "%s: '", msg);
      for (unsigned i=0; i < len; i++) 
         if (isascii(buf[i]))
            fputc(buf[i], stderr);
         else fprintf(stderr, "\\x%x", buf[i]);
      fprintf(stderr, "'\n");
   }
   exit(1);
}

size_t nread() {
   return nbytes;
}

size_t nwritten() {
   return numwritten;
}

size_t calls() {
   return ncalls;
}

char sbuf[1<<20];
size_t bidx;
bool batch_write=
#ifdef CAPTURE_ONLY
   true;
#else
   false;
#endif
size_t wbufsize=sizeof(sbuf)-8;

#ifdef DEBUG
long lh[64];
long prev_ncalls;
#endif

size_t dowrite() {
#ifdef CAPTURE_ONLY
   if (cap_state == OPEN && bidx != 0) {
      ssize_t nwritten;
      nwrites++;
      if ((nwritten = write(capture_fd, sbuf, bidx)) != (ssize_t)bidx) {
         if (nwritten < 0)
            errExit("Write failed");
         else errExit("Write call wrote fewer than requested bytes");
      }
      numwritten += bidx;
      bidx = 0;
#ifdef DEBUG
      long batch = ncalls - prev_ncalls;
      if (0 <= batch && batch < 64)
         lh[batch]++;
      else fprintf(stderr, "Error: Unexpected batch size (%ld)\n", batch);
      prev_ncalls = ncalls;
#endif
   }
#endif
   return 0;
}

static int
emit(void* buf, int sz) {
   if (sz <= 0)
      errExit("Consumer: Write error");

   if (cap_state == OPEN) {
      if (batch_write) {
         if (sz+bidx >= wbufsize)
            dowrite();
         if (sz+bidx < sizeof(sbuf)-8) {
            memcpy(sbuf+bidx, buf, sz);
            bidx += sz;
         }
      }
      else {
         ssize_t nwritten;
         if ((nwritten = write(capture_fd, buf, sz)) != sz) {
            if (nwritten < 0)
               errExit("Write failed");
            else errExit("Write call wrote fewer than requested bytes");
         }
         numwritten += sz;
      }
   }
   else if (cap_state == CLOSED)
      fprintf(stderr, "Receiving data after end_op\n");

#ifndef CAPTURE_ONLY
   if (parser_on)
      parse_rec((const char *)buf, sz);
#else
   assert(!parser_on);
#endif

   return 0;
}

static void gettime(clockid_t cid, uint64_t& ts) {
   struct timespec tspec;
   if (clock_gettime(cid, &tspec) < 0)
      errExit("Unable to read clock");
   ts = tspec.tv_sec*1000000000 + tspec.tv_nsec;      
}

uint64_t killtime;
void
tsighandler(int sig) {
   gettime(CLOCK_MONOTONIC, killtime);
   return;
}

static void
emit_clk_diff_rec(bool flag) {
   uint64_t realtime_ts; 
   static uint64_t monotonic_ts;

   if (flag) {
      static uint8_t ts_kern_rec[sizeof(uint64_t)+1] = {TS_KERN};
      *(uint64_t*)(&ts_kern_rec[1]) = killtime;
      emit(ts_kern_rec, sizeof(ts_kern_rec));
   }
   else{
      gettime(CLOCK_REALTIME, realtime_ts);
      gettime(CLOCK_MONOTONIC, monotonic_ts);

      static uint8_t ts_diff_rec[sizeof(uint64_t)+1] = {TS_DIFF};
      *(uint64_t*)(&ts_diff_rec[1]) = realtime_ts - monotonic_ts;
      emit(ts_diff_rec, sizeof(ts_diff_rec));
   }
}

size_t init_consumer(const char*  capture_fn, const char* prt_fn,
                                     const char* record_fn) {
   if (capture_fn && *capture_fn != '\0') {
      if (strcmp(capture_fn, "-") == 0) {
         if (isatty(1))
            exitError("(binary) audit data cannot be output on terminal");
         if ((prt_fn && *prt_fn == '-') || (record_fn && *record_fn == '-'))
            exitError("Capture file must be distinct from print/record files");
         capture_fd = 1;
      }
      else if ((capture_fd = open(capture_fn, O_CREAT|O_TRUNC|O_WRONLY, 0660)) < 0)
         errExit("Unable to open output file");
      cap_state = OPEN;
   }

   if ((prt_fn && *prt_fn) || (record_fn && *record_fn)) {
#ifdef CAPTURE_ONLY
      exitError("Print and record features not included in this binary");
#else
      if (isatty(1) && ((prt_fn && strcmp(prt_fn, "-") == 0) ||
                        (record_fn && strcmp(record_fn, "-") == 0)))
            exitError("audit data cannot be output on terminal");
      parser_on = true;
      parser_init(nullptr, prt_fn, record_fn);
#endif
   }

   signal(SIGUSR1, tsighandler);
   return 0;
}

int 
logprinter(void *x, void *buf, int sz) {
   static long tsync_n=-1000*1000*1000;

   nbytes += (unsigned)sz;

   if (!(ncalls & 0xfffff))
      fprintf(stderr, "Logprinter: %ldM records, average size %ld\n", 
              (ncalls+1)>>20, nbytes/(ncalls+1));

   if (!((ncalls++) & 0xfff) && ncalls > 0xfff)
       gettime(CLOCK_MONOTONIC, killtime);

   if (killtime) {
      emit_clk_diff_rec(true);
      tsync_n = nbytes;
      killtime = 0;
   }
   if (nbytes - tsync_n > 20000) { // Tweak for performance and latency
      emit_clk_diff_rec(false);
      tsync_n = nbytes;
   }

   return emit(buf, sz);
}

size_t end_op() {
   fprintf(stderr, "\nPid %d: Read %ldB in %ld msgs, avg msglen %ld, "
           "wrote %ldB\n", getpid(), nbytes, ncalls, nbytes/ncalls, numwritten);
   fprintf(stderr, "Writes=%lu\n", nwrites);
   cap_state = CLOSED;
#ifdef CAPTURE_ONLY
#ifdef DEBUG
   long tot=0;
   for (int j=0; j < 64; j++)
      if (lh[j]) {
         tot += lh[j];
         fprintf(stderr, "Bin %2d: %ld\n", j, lh[j]);
      }
   fprintf(stderr, "Total: %ld\n", tot);
#endif
#else
   if (parser_on)
      parser_finish();
#endif
   return 0;
}

