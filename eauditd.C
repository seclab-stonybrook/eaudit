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
#include <pthread.h>

#include "eauditd.h"
#include "eauditk.h"

using namespace std;

#ifdef CAPTURE_ONLY
#include "cmdln.C"
#else
#include "eParser.h"
#endif

int capture_fd=-1;
FILE *popen_fp;
enum CaptureState {NOT_ENABLED, OPEN, CLOSED};
CaptureState cap_state;
static size_t nbytes, ncalls, numwritten, numread_and_written;
size_t nwrites;
bool parser_on;
// Effective cache-flush polling interval in seconds. It defaults from
// max_cache_time passed by eauditd.py, but may be overridden by user -f.
float flushInterval;

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

long nread() {
   return nbytes;
}

long nwritten() {
   // NOTE: return value is valid immediately after a call to dowrite, or if
   // batch_write is false. It returns the size of actual data written, 
   // excluding any timestamps added in this file.

   return numread_and_written;
}

long calls() {
   return ncalls;
}

/*******************************************************************************
 * Batching multiple data packets into a single write reduces overheads.
 * If we are not careful, batching can increase the time during which data is
 * buffered --- and is hence vulnerable to attacks aimed at corrupting log data.
 * So, we allow data to be buffered *only* if we know that we are in the midst
 * of a batch, and that all the buffered data will be written at the end of a
 * batch. Specifically, we allow data to be buffered in between the callbacks
 * that result from a single call to ring_buffer_poll(). At the end of this,
 * dowrite() should be invoked to write out all the data. This way, there is no
 * idle period between the time data is buffered at the user level and it is
 * written to the file. (This batching has a significant effect on overhead ---
 * specifically, it reduces the system time of eauditd significantly.)
*******************************************************************************/

const size_t wbufsize = (1<<20);
char* sbuf;
size_t bidx;
bool batch_write=true
;

#ifdef DEBUG
long lh[64];
long prev_ncalls;
#endif

long dowrite() {
   // This should be called at the end of a batch of calls to logprinter()
   if (cap_state == OPEN && bidx != 0) {
      ssize_t nwritten;
      nwrites++;
      if ((nwritten = write(capture_fd, sbuf, bidx)) != (ssize_t)bidx) {
         if (nwritten < 0)
            errExit("Write failed");
         else errExit("Write call wrote fewer than requested bytes");
      }
      bidx = 0;
#ifdef DEBUG
      long batch = ncalls - prev_ncalls;
      if (0 <= batch && batch < 64)
         lh[batch]++;
      else fprintf(stderr, "Error: Unexpected batch size (%ld)\n", batch);
      prev_ncalls = ncalls;
#endif
   }
   return ncalls;
}

static int
emit(void* buf, int sz, bool flg) {
   if (sz <= 0)
      errExit("Consumer: Write error");

   if (cap_state == OPEN) {
      if (batch_write) {
         if (sz+bidx >= (wbufsize-8))
            dowrite();
         //assert(sz+bidx < (wbufsize-8));
         memcpy(sbuf+bidx, buf, sz);
         bidx += sz;
      }
      else {
         ssize_t nwritten;
         nwrites++;
         if ((nwritten = write(capture_fd, buf, sz)) != sz) {
            if (nwritten < 0)
               errExit("Write failed");
            else errExit("Write call wrote fewer than requested bytes");
         }
      }
      numwritten += sz;
      if (flg)
         numread_and_written += sz;
   }
   else if (cap_state == CLOSED)
      fprintf(stderr, "Receiving data after end_op\n");

#ifndef CAPTURE_ONLY
   if (parser_on)
      parse_rec((const char *)buf, sz);
#endif

   // @@@@ TODO: return a feedback based on drate. The feedback will throttle
   // @@@@ data production rate to achieve stability.

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
      emit(ts_kern_rec, sizeof(ts_kern_rec), false);
   }
   else{
      gettime(CLOCK_REALTIME, realtime_ts);
      gettime(CLOCK_MONOTONIC, monotonic_ts);

      static uint8_t ts_diff_rec[17] = {TS_DIFF};
      *(uint64_t*)(&ts_diff_rec[1]) = realtime_ts;
      *(uint64_t*)(&ts_diff_rec[9]) = monotonic_ts;
      emit(ts_diff_rec, sizeof(ts_diff_rec), false);
   }
}

extern bool online_mode;
extern float user_flushInterval;
extern long tamperWindow;
bool twin_end;

void* 
poll_forever(void *ptr) {
   long dur = (long)ptr;
   int pid = getpid();
   long twin = tamperWindow? tamperWindow : 100;
   if (dur >= 100) {
      fprintf(stderr, "Cache flushing thread running");
      for (long j=0, l=0; j < 1e15; j++, l++) {
         if (usleep(dur)) {
            perror("usleep failed");
            break;
         }

         if (kill(pid, 0)) {
            perror("kill failed");
            break;
         }

         if (l == twin) {
            l = 0;
            twin_end = true;
            //fprintf(stderr, ".");
         }
      }
      fprintf(stderr, "Cache flushing thread exiting\n");
   }
   else fprintf(stderr, 
                "Sleep time %ld < 100 microsecond minimum, exiting\n", dur);
   return NULL;
}

void setup_popen(const char* cap_file, FILE*& fp, int& fd) {
   char host[strlen(cap_file)+1] = "";
   char cmd[64+2*strlen(cap_file)+1] = "";
   const char* fn = index(cap_file, ':');
   if (!fn)
      errExit("Invalid file name specification. Run with -h for help.");
   else fn++;
   if (*fn == '/' && *(fn+1) == '/') {
      fn += 2;
      unsigned j = 0;
      while (*fn && *fn != '/')
         host[j++] = *fn++;
      host[j] = '\0';
      if (*fn == '/')
         fn++;
   }

   if (strstr(cap_file, "gzip:") == cap_file)
      sprintf(cmd, "gzip -c -n > %s", fn);
   else if (strstr(cap_file, "gzipfast:") == cap_file)
      sprintf(cmd, "gzip -c -n --fast > %s", fn);
   else if (strstr(cap_file, "ssh:") == cap_file)
      sprintf(cmd, "ssh %s 'cat > %s'", host, fn);
   else if (strstr(cap_file, "ssh+gzip:"))
      sprintf(cmd, "ssh %s 'gzip -c -n > %s'", host, fn);
   else if (strstr(cap_file, "ssh+gzipfast:"))
      sprintf(cmd, "ssh %s 'gzip -c -n --fast > %s'", host, fn);
   else if (strstr(cap_file, "gzip+ssh:"))
      sprintf(cmd, "gzip -c -n | ssh %s 'cat > %s'", host, fn);
   else if (strstr(cap_file, "gzipfast+ssh:"))
      sprintf(cmd, "gzip -c -n --fast | ssh %s 'cat > %s'", host, fn);
   else errExit("Invalid file name specification. Run with -h for help.");

   fprintf(stderr, "Calling popen with command: %s\n", cmd);
   fp = popen(cmd, "w");
   if (!fp)
      errExit("Unable to open output file");
   fd = fileno(fp);
}

long init_consumer(int argc, const char* argv[]) {
   //fprintf(stderr, "init(%d, ", argc);
   //for (int j=0; j < argc; j++)
   //   fprintf(stderr, (j==argc-1)? "%s" : "%s, ", argv[j]);
   //fprintf(stderr, ")\n");

   sbuf = new char[wbufsize];
   online_mode = true;
   // flushInterval is the daemon's effective polling interval. Its default is
   // 3 * max_cache_time, converted from nanoseconds to seconds. With the Python
   // default max_cache_time of about 1 ms, this makes flushInterval about 3 ms.
   // user_flushInterval is different: it is only the optional user-provided
   // override from "-f <seconds>", and replaces flushInterval when set.
   flushInterval = (3 * strtof(argv[1], NULL) / 1e9);  
   parseCmdLine(argc, argv);
   if (user_flushInterval > 0) 
      flushInterval = user_flushInterval;  
   
   if (capturefn && *capturefn) {
      if (strcmp(capturefn, "-") == 0) {
         if (isatty(1))
            exitError("(binary) audit data cannot be output on terminal");
         capture_fd = 1;
      }
      else if (index(capturefn, ':'))
         setup_popen(capturefn, popen_fp, capture_fd);
      else if ((capture_fd = open(capturefn, O_CREAT|O_TRUNC|O_WRONLY, 0660)) < 0)
         errExit("Unable to open output file");
      cap_state = OPEN;
   }

   if ((prtpfn && *prtpfn) || (prtcfn && *prtcfn) || (recfn && *recfn)) {
#ifdef CAPTURE_ONLY
      exitError("Print and record features not included in this binary");
#else
      parser_init();
      parser_on = true;
#endif
   }

   pthread_t flush_thread;
   if (flushInterval > 0)
     pthread_create(&flush_thread, NULL, poll_forever, 
                    (void*) (long)(0.5+flushInterval*1e6));

   signal(SIGUSR1, tsighandler);
   signal(SIGPIPE, SIG_IGN);
   return 0;
}

// @@@@ TODO: Write a header record that includes all config params
long
logprinter(void *x, void *buf, int sz) {
   static long tsync_n=-1000*1000*1000;
   if (sz <= 0) {
      fprintf(stderr, "*********** Invalid data size %d\n", sz);
      return 0;
   }
   if (*(char*)buf != TSMS_EN) {
      static int n;
      n++;
      if (n < 10)
         fprintf(stderr, "UNEXPECTED MSG START %c\n", *(char*)buf);
   }

   nbytes += (unsigned)sz;

   if (!(ncalls & 0xfffff))
      fprintf(stderr, "Logprinter: %ldM records, average size %ld\n", 
              (ncalls+1)>>20, nbytes/(ncalls+1));

   ncalls++;

   // @@@@ Clean this up: Outputting TS_DIFF every 20K bytes seems reasonable,
   // @@@@ but it is not good to hardcode TS_KERN to 4K calls of logprinter.
   // @@@@ Change to be externally controllable, based on # of bytes or time

   if (flushInterval > 0) {
      if (twin_end) {
         twin_end = false;
         gettime(CLOCK_MONOTONIC, killtime);
         // @@@@ This way makes it easier to compare old and new methods. For
         // @@@@ a more accurate estimate, other thread shd directly set killtime.
      }
   }
   else if (!(ncalls & 0xfff) && ncalls > 0xfff)
       gettime(CLOCK_MONOTONIC, killtime);

   if (killtime) {
      emit_clk_diff_rec(true); // emit TS_KERN record, used for tamper windows
      killtime = 0;
   }

   if (nbytes - tsync_n > 20000) {
      emit_clk_diff_rec(false); // emit TS_DIFF record, to convert kernel 
      tsync_n = nbytes;         // timestamps to real time.
   }

   return emit(buf, sz, true);
}

long end_op() {
   fprintf(stderr, "\nPid %d: Read %ldB in %ld msgs, avg msglen %ld, "
           "%ldB in %lu writes (avg=%ldB)\n", getpid(), nbytes, ncalls, 
           (long)(0.5+nbytes/(ncalls+0.01)), numwritten, nwrites, 
           (long)(0.5+numwritten/(nwrites+.01)));
   if (popen_fp)
      pclose(popen_fp);
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
