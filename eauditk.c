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

#include <uapi/asm-generic/siginfo.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/asm-generic/mman.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/capability.h>
#include <uapi/linux/fs.h>

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/ipv6.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>

#include "eauditk.h"

#define mymin(x, y) ((x) < (y) ? (x) : (y))
/****************************************************************************** 
 * Start with some helper functions for accessing status/error counters.      *
 *****************************************************************************/
static inline void incr_sc_entry(int sc) { count.atomic_increment(sc); }

static inline void fcntl_err() { mystat.atomic_increment(FCNTL_ERR); }
static inline void pipe_err() { mystat.atomic_increment(PIPE_ERR); }
static inline void saddr_err() { mystat.atomic_increment(SADDR_ERR); }
static inline void mmap_err() { mystat.atomic_increment(MMAP_ERR); }
static inline void string_err() { mystat.atomic_increment(FN_ERR); }
static inline void data_read_ok() { mystat.atomic_increment(DATA_READ_OK); }
static inline void string_trunc_err() { mystat.atomic_increment(FN_TRUNC_ERR); }
static inline void data_trunc_err() { mystat.atomic_increment(DATA_TRUNC_ERR); }
static inline void argv_err() { mystat.atomic_increment(ARGV_ERR); }

static inline void pipe_read_data_err() 
  { mystat.atomic_increment(PIPE_READ_DATA_ERR); }
static inline void saddr_read_data_err() 
  { mystat.atomic_increment(SADDR_READ_DATA_ERR); }
static inline void saddr_data_err() { mystat.atomic_increment(SADDR_DATA_ERR); }
static inline void conn_data_err() { mystat.atomic_increment(CONN_DATA_ERR); }
static inline void sendto_data_err()  { mystat.atomic_increment(SENDTO_DATA_ERR);}
static inline void bind_data_err()  { mystat.atomic_increment(BIND_DATA_ERR);}

static inline void inc_subj(){mystat.atomic_increment(NUM_SUBJ_CREATED);}

/****************************************************************************** 
 ******************************************************************************
 * Helper functions for marshalling data, i.e., copy data into the per-CPU    *
 * buffer and update the relevant header fields.                              *
 *****************************************************************************/
static inline u8 addLong(u8* buf, long v) {
   char v0 = v & 0xff;
   if (v0 == v) {
      *buf = v0;
      return 0;
   }
   short v1 = v & 0xffff;
   if (v1 == v) {
      *(u16*)buf = v1;
      return 1;
   }
   int v2 = v & 0xffffffff;
   if (v2 == v) {
      *(u32*)buf = v2;
      return 2;
   }
   *(u64*)buf = v;
   return 3;
}

/******************************************************************************
 * The following three functions, in addition to adding long arguments to the *
 * buffer, additionally set header fields to indicate their lengths. There    *
 * enough bits to support this variable length encoding for up to 3 long args.*
 *****************************************************************************/
static inline void 
add_long1(struct buf* b, long a1, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   b->d[hdr] |= (sz1<<4);
}

static inline void 
add_long2(struct buf* b, long a1, long a2, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   u8 sz2 = addLong(&b->d[*idx], a2);
   *idx += (1<<sz2);
   b->d[hdr] |= (sz1<<4) | (sz2<<2);
}

static inline void 
add_long3(struct buf* b, long a1, long a2, long a3, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   u8 sz2 = addLong(&b->d[*idx], a2);
   *idx += (1<<sz2);
   u8 sz3 = addLong(&b->d[*idx], a3);
   *idx += (1<<sz3);
   b->d[hdr] |= (sz1<<4) | (sz2<<2) | sz3;
}

/******************************************************************************
 * More helper functions for adding strings, adding multiple strings, and     *
 * length-prefixed binary data.                                               *
 *****************************************************************************/
static inline void
add_string(struct buf* b, const char* fn, u16 *idx) {
   *idx += 1; // Space for the length byte.
   int n = bpf_probe_read_str(&b->d[*idx], min(MAX_SLEN, BUFSIZE-(*idx)-3), fn);
   // n = max(n, 1);

   if (n < 0) {
      string_err();
      n = 0;
   }
   // Invariant: n >= 0

   b->d[*idx-1] = n; // Set string length, including trailing null
   *idx += n;        // Advance index by string length.
}
static inline void
add_str_array0_16(struct buf* b, const char* const *argv, u16 *idx) {
   u8 *nargs = &b->d[*idx]; (*idx)++;
   *nargs = 0;   

   const char* argarray[16];
   const char** arga = argarray;

   if (bpf_probe_read_user(argarray, sizeof(argarray), argv)) {
      argv_err();
      return;
   }

   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #1
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #2
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #3
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #4
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #5
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #6
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #7
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #8
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #9
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #10
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #11
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #12
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #13
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #14
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #15
   if (!*arga) return;
   add_string(b, *arga, idx); arga++; (*nargs)++; // arg #16
}

static inline int
add_data(struct buf* b, u8* data, int dlen, u16 *idx) {
   int fail=0;
   u8 len = min(MAX_DLEN, dlen);
   if (0 < len && len <= BUFSIZE-(*idx)-3) {
      fail = bpf_probe_read(&b->d[1+*idx], len, data);
      if (fail) {
         //data_err();
         len = 0;
      }
      if (len == MAX_DLEN)
         data_trunc_err();
      else data_read_ok();
   }
   else len = 0;
   b->d[*idx] = len;
   *idx += len+1; // Advance index by length plus space for len field.
   return fail;
}

/****************************************************************************** 
 ******************************************************************************
 * The sole function for copying data from per-CPU buffer b to ring buffer.   *
 * Wakes up user level if the combined weight of messages b (i.e., b->weight) *
 * exceeds TX_WT_THRESH, or once per RINGBUF_PUSH_INTERVAL calls of xmit.     *
 *****************************************************************************/
static inline void check_xmit(struct buf* b, u16 *i, u64 ts, int force) {
   if ((*i >= TX_THRESH) || (ts && MS_BITS(ts) != b->ts_msbs) || force) {
      b->ts_msbs = TS_RECORD(b->ts_msbs);
      int sz = *i + 8; // Add the size of TSMS record
      if (sz < BUFSIZE) { // Always true, but verifier may need help.
         mystat.atomic_increment(RB_MSGS); // # of msgs ATTEMPTED to send
         u32 rnd = bpf_get_prandom_u32();
         int err;
         // NOTE: we cannot use the reserve/commit API because the verifier
         // requires the size to be a compile-time constant. 
         if ((b->weight >= TX_WT_THRESH) || 
             (rnd < (((u32)-1)/RINGBUF_PUSH_INTERVAL))) {
            err = events.ringbuf_output(&b->ts_msbs, sz, BPF_RB_FORCE_WAKEUP);
            mystat.atomic_increment(RB_WAKEUPS);
         }
         else err = events.ringbuf_output(&b->ts_msbs, sz, BPF_RB_NO_WAKEUP);
         if (err)
            mystat.atomic_increment(RB_FAIL);
         mystat.atomic_increment(RB_BYTES, sz); // # of bytes ATTEMPTED to send
      }

      b->weight = 0;
      *i = 0;
      if (ts==0) 
         ts = bpf_ktime_get_ns();
      b->ts_msbs = MS_BITS(ts);
   }
}

BPF_ARRAY(seqn, u32, 1);    // To assign sequence numbers (if used)
static inline 
u32 getSeqNum() {
#ifdef INCL_SEQNUM
      u32 sn=0;
      u32* snp = seqn.lookup(&sn);
      if (snp) {
         // A read before AND after seems to reduce the range of possible values,
         // i.e., reduces duplicate sequence numbers. 
         sn = (u16)*snp;
         lock_xadd(snp, 1);
         u16 sn1 = *snp;
         if (sn == sn1)
           sn = 0;
      }
      return sn;
#else
      return 0;
#endif
}

/****************************************************************************** 
 ******************************************************************************
 * Functions for initializing a new event record.                             *
 *                                                                            *
 *   (a) init is used to initialize an _entry_ record. It updates the total   *
 *       weight of the message (b->weight) but the other helpers don't.       *
 *       It calls xmit to copy the per-CPU buffer b into the ring buffer when *
 *       it is too full (idx >= TX_THRESH) or if the MS bits of the timestamp *
 *       has changed from the one in the header of this message.              *
 *                                                                            *
 *   (b) initx is similar, but used for initializing a system call _exit_     *
 *       record. For most system calls, the user level takes their entry time *
 *       as the time of occurrence of the system call. For this reason, it is *
 *       OK if the timestamp for the exit event is inaccurate. Hence we skip  *
 *       the MS bits check in this function.                                  *
 *                                                                            *
 *   (c) initxt is similar to initx, but does NOT skip MS_BITS check. It is   *
 *       used for system calls that may return arbitrarily long after the     *
 *       entry, such as read. The user level relies on the timestamp of the   *
 *       exit record for such system calls.                                   *
 *****************************************************************************/
static inline struct buf* 
init(int sc, char scnm, int scwt, u16 *idx, u16*hdr) {
   incr_sc_entry(sc);
   int z = 0;
   struct buf* b = buf.lookup(&z);
   if (b) {
      *idx = b->idx;
      u64 ts = bpf_ktime_get_ns(); 
      check_xmit(b, idx, ts, 0);

      u32 sn = getSeqNum();

      b->d[*idx] = scnm; (*idx)++;

#ifdef INCL_SEQNUM
      *(u16*)(&b->d[*idx]) = (u16)sn; *idx += 2;
#endif
#ifdef INCL_PROCID
      b->d[*idx] = bpf_get_smp_processor_id() & 0xff; *idx += 1;
#endif

#ifdef FULL_TIME
      *(u64*)(&b->d[*idx]) = ts; *idx += 8;
#else
      // Store just the LS bits. MS bits are stored in the header.
      // @@@@ The following line likely works only for little endian
      *(u32*)(&b->d[*idx]) = (u32)(LS_BITS(ts)); *idx += MS_BIT_SHIFT/8;
#endif

      *hdr = *idx; (*idx)++;

      u64 pidtid = bpf_get_current_pid_tgid(); 
      u64 pid = (pidtid >> 32);
      if ((pidtid & 0xffffffff) == pid)
         pidtid = pid; // single-threaded process, just record pid
      u8 sz = addLong(&b->d[*idx], pidtid);
      *idx += (1<<sz);
      b->d[*hdr] = (sz<<6);
      b->weight += scwt;
      return b;
   }
   return 0;
}

static inline struct buf* 
initx(int sc, char scnm, u16 *idx, u16*hdr) {
   int z = 0;
   struct buf* b = buf.lookup(&z);
   if (b) {
      *idx = b->idx;
      check_xmit(b, idx, 0, 0);

      u32 sn = getSeqNum();

      b->d[*idx] = scnm; (*idx)++;

#ifdef INCL_SEQNUM
      *(u16*)(&b->d[*idx]) = (u16)sn; *idx += 2;
#endif
#ifdef INCL_PROCID
      b->d[*idx] = bpf_get_smp_processor_id() & 0xff; *idx += 1;
#endif

      *hdr = *idx; (*idx)++;

      u64 pidtid = bpf_get_current_pid_tgid(); 
      u64 pid = (pidtid >> 32);
      if ((pidtid & 0xffffffff) == pid)
         pidtid = pid; // single-threaded process, just record pid
      u8 sz = addLong(&b->d[*idx], pidtid);
      *idx += (1<<sz);
      b->d[*hdr] = (sz<<6);
      return b;
   }
   return 0;
}

static inline struct buf* 
initxt(int sc, char scnm, int scwt, u16 *idx, u16*hdr) {
   int z = 0;
   struct buf* b = buf.lookup(&z);
   if (b) {
      *idx = b->idx;
      u64 ts = bpf_ktime_get_ns(); 
      check_xmit(b, idx, ts, 0);

      u32 sn = getSeqNum();

      b->d[*idx] = scnm; (*idx)++;
#ifdef INCL_SEQNUM
      *(u16*)(&b->d[*idx]) = (u16)sn; *idx += 2;
#endif
#ifdef INCL_PROCID
      b->d[*idx] = bpf_get_smp_processor_id() & 0xff; *idx += 1;
#endif

#ifdef FULL_TIME
      *(u64*)(&b->d[*idx]) = ts; *idx += 8;
#else
      // Store just the LS bits. MS bits are stored in the header.
      *(u32*)(&b->d[*idx]) = (u32)(LS_BITS(ts)); *idx += MS_BIT_SHIFT/8;
#endif

      *hdr = *idx; (*idx)++;

      u64 pidtid = bpf_get_current_pid_tgid(); 
      u64 pid = (pidtid >> 32);
      if ((pidtid & 0xffffffff) == pid)
         pidtid = pid; // single-threaded process, just record pid
      u8 sz = addLong(&b->d[*idx], pidtid);
      *idx += (1<<sz);
      b->d[*hdr] = (sz<<6);
      b->weight += scwt;
      return b;
   }
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Counterpart of the init functions above: finish() is used to complete an   *
 * event record. It checks the thresholds --- buffer length as well as the    *
 * weight threshold. If they are over the thresholds, xmit() is called. Since *
 * scwt is updated only on entry events, b->weight >= TX_WT_THRESH))          *
 * can hold in finish _only_ for entry events. For exit events, the buffer    *
 * would already have been emptied on the previous operation if it exceeded   *
 * the threshold. THIS MEANS THAT weight-based copying into ring buffer and   *
 * the prompt wake up of user level are possible ONLY for entry events. This  *
 * seems OK, as most dangerous system calls should be treated as if they      *
 * occurred at the time of their entry into the kernel.                       *
 *****************************************************************************/
static inline void
finish(struct buf *b, u16 i) {
#ifdef PADDING_SIZE // Add a padding of size PADDING_SIZE
   char padding[PADDING_SIZE/2+1] = {0}; // add_data sends up to 128 bytes. By
   add_data(b, padding, PADDING_SIZE/2, &i); // calling it twixe, padding size
   add_data(b, padding, (PADDING_SIZE+1)/2, &i); // <256 bytes can be supported.
#endif
   b->d[i] = '\n'; 
   i++;
   check_xmit(b, &i, 0, (b->weight >= TX_WT_THRESH));
   b->idx = i;
}

/****************************************************************************** 
 ******************************************************************************
 * Higher level marshalling functions. The lower level marshalling functions  *
 * handled a single argument or a single set of arguments. These higher level *
 * functions prepare the complete record: they call one of the init functions *
 * then add all the relevant arguments, and finally call the finish function  *
 * to complete the record. We have several of them below, one for each        *
 * system call entry/exit that is distinct in terms of argument types. Their  *
 * names indicate argument types. An x at the end of the name indicates that  *
 * this is a system call exit event, while xt indicates that it is an exit    *
 * event with a significant timestamp (so it should call initxt, not initx).  *
 *                                                                            *
 * Note that most system calls exits have just a return value to send back to *
 * the user level, so sc_exit() and sc_exitt() are the most frequently used   *
 * for marshalling an exit record. But some system call exits have more data  *
 * return, e.g., an accept system call that returns the information of the    *
 * connected peer. The remaining x() and xt() functions are used for them.    *
 *****************************************************************************/
static inline void 
log_sc_long0(int sc, char scnm, int scwt) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      finish(b, i);
   }
}

static inline void 
log_sc_long1(int sc, char scnm, int scwt, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_long2(int sc, char scnm, int scwt, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_long3(int sc, char scnm, int scwt, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_long3int(int sc, char scnm, int scwt, long a1, long a2, long a3, int a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      *(u32*)(&b->d[i]) = a4; i += 4;
      finish(b, i);
   }
}

static inline void 
log_sc_str_long0(int sc, char scnm, int scwt, const char* fn) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_string(b, fn, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str_long1(int sc, char scnm, int scwt, const char* fn, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str_long2(int sc, char scnm, int scwt, const char* fn, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str_long3(int sc, char scnm, int scwt, const char* fn, long a1, long a2, 
                 long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str2_long1(int sc, char scnm, int scwt, const char* s1, const char* s2, 
                  long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str2_long2(int sc, char scnm, int scwt, const char* s1, const char* s2, 
                  long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i);
   } 
}

static inline void 
log_sc_str2_long3(int sc, char scnm, int scwt, const char* s1, const char* s2, 
                  long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i);
   } 
}

static inline int
log_sc_data_long1(u64 sc, char scnm, int scwt, void* data, int len, long a1) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i);
   } 
   return fail;
}

static inline void 
log_sc_exit(int sc, char scnm, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initx(sc+400, scnm, &i, &hdr))) {
      add_long1(b, ret, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_exit2(int sc, char scnm, long a, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initx(sc+400, scnm, &i, &hdr))) {
      add_long2(b, a, ret, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_exitt(int sc, char scnm, int scwt, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initxt(sc+400, scnm, scwt, &i, &hdr))) {
      add_long1(b, ret, &i, hdr);
      finish(b, i);
   }
}

static inline int
log_sc_data_long1x(u64 sc, char scnm, void* data, int len, long ret) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = initx(sc, scnm, &i, &hdr))) {
      add_long1(b, ret, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i);
   } 
   return fail;
}

static inline int
log_sc_data_long1xt(u64 sc, char scnm, int wt, void* data, int len, long ret) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = initxt(sc, scnm, wt, &i, &hdr))) {
      add_long1(b, ret, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i);
   }
   return fail;
}

static inline void
log_sc_long2x(u64 sc, char scnm, long a1, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initx(sc, scnm, &i, &hdr))) {
      add_long2(b, a1, ret, &i, hdr);
      finish(b, i);
   }
}

static inline void
log_sc_long2xt(u64 sc, char scnm, int wt, long a1, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initxt(sc, scnm, wt, &i, &hdr))) {
      add_long2(b, a1, ret, &i, hdr);
      finish(b, i);
   }
}

static inline int
log_sc_data_long2xt(u64 sc, char scnm, int wt, void* data, int len, 
                    long a1, long ret) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = initxt(sc, scnm, wt, &i, &hdr))) {
      add_long2(b, a1, ret, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i);
   }
   return fail;
}

static inline void 
log_sc_long3x(int sc, char scnm, long a1, long a2, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initx(sc, scnm, &i, &hdr))) {
      add_long3(b, a1, a2, ret, &i, hdr);
      finish(b, i);
   }
}

static inline void 
log_sc_long3xt(int sc, char scnm, int scwt, long a1, long a2, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initxt(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, ret, &i, hdr);
      finish(b, i);
   }
}

static inline void
sc_str_long3_exitt(int sc, char scnm, int wt, const char* s1,
                   long a1, long a2, long ret) {
   u16 i, hdr; struct buf *b;
   if ((b = initxt(sc, scnm, wt, &i, &hdr))) {
      add_long3(b, a1, a2, ret, &i, hdr);
      add_string(b, s1, &i);
      finish(b, i);
   }
}

static inline int
sc_str_data_long3_exitt(int sc, char scnm, int wt, const char* s1,
                   void* data, int len, long a1, long a2, long ret) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = initxt(sc, scnm, wt, &i, &hdr))) {
      add_long3(b, a1, a2, ret, &i, hdr);
      add_string(b, s1, &i);
      fail = add_data(b, data, len, &i);
      finish(b, i);
   }
   return fail;
}

/****************************************************************************** 
 ****************************************************************************** 
 * Often, we need to remember some context between calls and returns, e.g.,   *
 * to store some pointer arguments on sys_enter and then retrieve target mem  *
 * in sys_exit. In other cases, we want to intercept an exit only if we       *
 * intercepted the entry. We can use a single map for all these cases, since  *
 * the information needs to be remembered between two successive events from  *
 * the same pid. But we use more than one because some syscalls require more  *
 * info to be stored, e.g., information about remote address in an accept.    *
 * For the rest, we fix the value to be u64 and reuse a single map.           *
 *****************************************************************************/
static inline int 
gettid() {
   // Lower 32 bits encode task/thread id, so no addl computation needed.
   return bpf_get_current_pid_tgid();
}

static inline int 
getpid() {
   return bpf_get_current_pid_tgid() >> 32;
}

// We define a per-task map for stashing syscall arguments between entry and
// exit. We use a separate map just for args, as opposed to consolidating into
// a struct that captures all task-related info. This make sense because it:
//  (a) Easier to separate and enable/disable features indedpendently
//  (b) Args are stored on almost every syscall, while the remaining task-related
//      info is accessed only for specific system calls, e.g., reads, opens, etc.
struct long3 {
   u64 d1;
   u64 d2;
   u64 d3;
};
BPF_TABLE("lru_hash", u32, struct long3, arg3, MAX_TASKS); 
// Entries are short-lived, from syscall entry to exit. So there is essentially
// no risk of LRU evicting valid entries. In fact, MAX_TASKS need not even be 
// very large: the number of simultaneously active syscalls can't be too high.
// Risks are minimal even if we consider attacks by non-root processes. And
// if we do run out of space, the worst possible result is a lost syscall.

// Because this map are initialized at syscall entry and cleaned up at exit,
// there is no chance of stale entries, or the risk of reuse when pids are
// recycled. No need for locks either, since each map is accessed using the 
// subject's tid, and one thread can be making only one syscall at a time.

static inline int
arg3_record(u64 sc, long l1, long l2, long l3, int tid) {
   struct long3 info = {l1, l2, l3};
   incr_sc_entry(sc);
   return arg3.update(&tid, &info);
}

static inline int
arg3_record1(u64 sc, long l1, long l2, long l3, int tid) {
   struct long3 info = {l1, l2, l3};
   return arg3.update(&tid, &info);
}

static inline int
arg3_retrieve_and_delete(long* l1, long* l2, long* l3, int tid) {
   struct long3* succ = arg3.lookup(&tid);
   if (succ) {
      *l1 = succ->d1;
      *l2 = succ->d2;
      *l3 = succ->d3;
      arg3.delete(&tid);
      return 1;
   }
   else return 0;
}

BPF_TABLE("lru_hash", u32, u64, arg, MAX_TASKS); 
// We use a second map for syscalls that need to stash just a single argument.
// Using a separate table in this case seems to have a small performance gain.
// All other points made above (regarding eviction, locks, etc.) are unchanged.

static inline int
arg_record(u64 sc, u64 d, int tid) {
   incr_sc_entry(sc);
   return arg.update(&tid, &d);
}

static inline int
arg_record1(u64 d, int tid) {
   return arg.update(&tid, &d);
}

static inline int
arg_retrieve_and_delete(u64* info, int tid) {
   u64* succ = arg.lookup(&tid);
   if (succ) {
      *info = *succ;
      arg.delete(&tid);
      return 1;
   }
   else return 0;
}

static inline int
arg_check_and_delete(int tid) {
   u64* succ = arg.lookup(&tid);
   if (succ) 
      arg.delete(&tid);
   return (succ != 0);
}

static inline void
add_si(u32 pid, int per_thread_fi, int add_thread) {
   inc_subj();
}

static inline void
store_open_args(u64 sc, const char* fn, int at_fd, int flags, int mode) {
   int wt = (flags & (O_APPEND | O_WRONLY | O_RDWR))? WT_OPENWR : WT_OPENRD;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= wt)
      arg3_record1(sc, (long)fn, at_fd, ((u64)mode << 32) | flags, gettid());
}

static inline void
log_open_exit(u64 sc, long ret) {
   u64 pid_tgid = bpf_get_current_pid_tgid();
   int tid = pid_tgid;
   int pid = pid_tgid >> 32;

   char *fn;
   long at_fd;
   long md_flags;

   if (arg3_retrieve_and_delete((long*)&fn, &at_fd, &md_flags, tid)) {
     if (!is_err(ret));
#ifndef REPORT_OPEN_ERRS
     else return;
#endif

     incr_sc_entry(sc);
     int wt = (md_flags & (O_APPEND|O_WRONLY|O_RDWR))? WT_OPENWR : WT_OPENRD;
     sc_str_long3_exitt(sc, OPEN_EX, wt, fn, md_flags, at_fd, ret);
   }
}

/****************************************************************************** 
 ******************************************************************************
 * pipe and socketpair take an array[2] as argument and fill them with fds.   *
 * We need to store the address of this array at the entry in a map. This map *
 * needs to be global because the return can go to a different CPU. On the    *
 * exit event, we need to read at this cached address and retrieve the fds.   *
 * We wrap this extra functionality into two helper functions pipe_enter and  *
 * that are used for pipe, pipe2 and socketpair.                              *
 *****************************************************************************/
static inline void
pipe_enter(u64 sc, char scnm, int* fds) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PIPE) {
      if (arg_record(sc, (u64)fds, gettid()))
         pipe_err();
   }
}

static inline void
pipe_exit(u64 sc, char scnm, long ret) {
   u64 pid_tgid = bpf_get_current_pid_tgid();
   int tid = pid_tgid;
   int pid = pid_tgid >> 32;
   int err = is_err(ret);
   int* fdaddr;
   if (arg_retrieve_and_delete((u64*)&fdaddr, tid)) {
      long fds;
      if (!err) {
         if (bpf_probe_read(&fds, 8, fdaddr)) {
            err = 1;
            pipe_read_data_err();
         }
         else ret = fds;
      }

      log_sc_exitt(sc, scnm, WT_PIPE, ret); 
   }
}

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto the main task: writing the handlers for each system call   *
 * entry and exit. We start with functions for opening a file. We record a    *
 * open as an openat, adding AT_FDCWD as an extra argument.                   *
 *****************************************************************************/
#ifdef LOG_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
   store_open_args(args->__syscall_nr, args->filename, AT_FDCWD, 
                   args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open) {
   log_open_exit(args->__syscall_nr, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
   store_open_args(args->__syscall_nr, args->filename, (int)args->dfd, 
                   args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
   log_open_exit(args->__syscall_nr, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
   store_open_args(args->__syscall_nr, args->pathname, AT_FDCWD, 
                   O_CREAT|O_WRONLY|O_TRUNC, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_creat) {
   log_open_exit(args->__syscall_nr, args->ret);
   return 0;
}

///////////////////////////////////////////////////////////////////////////
// Truncate is rare enough that we use the old scheme (log entry and exit).
// For the same reason, we also omit repeated read/write optimizations. 
// We also omit oids because our current oid computation requires fds.
TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      log_sc_str_long1(args->__syscall_nr, TRUNC_EN, WT_TRUNC, 
                       args->path, args->length);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      log_sc_exit(args->__syscall_nr, TRUNC_EX, args->ret);
   return 0;
   
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      log_sc_long2(args->__syscall_nr, FTRUNC_EN, WT_TRUNC, 
                   args->fd, args->length);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      log_sc_exit(args->__syscall_nr, FTRUNC_EX, args->ret);
   return 0;
}
#endif

// Log close entry because we most likely won't log close exit.
TRACEPOINT_PROBE(syscalls, sys_enter_close) {
   long unreported_read=0, unreported_write=0;

// @@@@ If unreported read, (and/or write) submit a read (and/or write) event

#ifdef LOG_CLOSE
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CLOSE) 
      log_sc_long3(args->__syscall_nr, CLOSE_EN, WT_CLOSE, (int)args->fd,
                   unreported_read, unreported_write);
#endif
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto a bunch of functions that change the meaning of file       *
 * descriptors, such as dup. Also included in this group is fcntl, which can  *
 * be used in place of dup. Because fcntl can be very frequent, we only track *
 * fcntl calls with the DUP operation code. The rest are ignored.             *
 *****************************************************************************/
#ifdef LOG_DUP
static inline void
dup_entry(u64 sc, int fd) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_DUP)
      arg_record(sc, fd, gettid());
}

static inline void
dup_exit(u64 sc, char scnm, int scwt, u64 ret) {
   long in_fd;
   u64 pid_tgid = bpf_get_current_pid_tgid();
   int tid = pid_tgid;
   int pid = pid_tgid >> 32;
   if (arg_retrieve_and_delete((u64*)&in_fd, tid)) {
      int newfd = ret;
      log_sc_long2xt(sc, scnm, scwt, in_fd, newfd);

   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup) {
   dup_entry(args->__syscall_nr, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup) {
   dup_exit(args->__syscall_nr, DUP_EX, WT_DUP, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
   dup_entry(args->__syscall_nr, args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2) {
   dup_exit(args->__syscall_nr, DUP2_EX, WT_DUP, args->ret);
   return 0;
}

// We will record dup2 and dup3 as dup2, ignoring the flag argument of dup3.
TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
   dup_entry(args->__syscall_nr, args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup3) {
   dup_exit(args->__syscall_nr, DUP2_EX, WT_DUP, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) { // Log only if it is DUP operation
   u64 cmd = args->cmd;
   if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)
      dup_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fcntl) {
   dup_exit(args->__syscall_nr, DUP_EX, WT_DUP, args->ret);
   return 0;
}
#endif

#ifdef LOG_PIPE
TRACEPOINT_PROBE(syscalls, sys_enter_pipe) {
   pipe_enter(args->__syscall_nr, PIPE_EN, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe) {
   pipe_exit(args->__syscall_nr, PIPE_EX, args->ret);
   return 0;
}

//@@@@ Protocol info is not being sent. fix.
TRACEPOINT_PROBE(syscalls, sys_enter_socketpair) {
   pipe_enter(args->__syscall_nr, SOCKPAIR_EN, args->usockvec);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socketpair) {
   pipe_exit(args->__syscall_nr, SOCKPAIR_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pipe2) {
   pipe_enter(args->__syscall_nr, PIPE_EN, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe2) {
   pipe_exit(args->__syscall_nr, PIPE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SOCKET)
      log_sc_long3(args->__syscall_nr, SOCKET_EN, WT_SOCKET, args->family, 
                     args->type, args->protocol);
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several network-related opertions. Many of them need to obtain    *
 * the socket address of the peer. As before, we use a hash map to record the *
 * address of the sockaddr structure, and then read from this location at the *
 * system call exit. A helper function store_saddr is used at the entry, and  *
 * log_sc_with_saddr at the exit. These helpers are reused across several     *
 * network-related system calls such as recvfrom, accept, getpeername, etc.   *
 *****************************************************************************/
static inline void
store_saddr_arg(int sc, int scwt, struct sockaddr* saddr, int* slen, long fd) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= scwt)
     arg3_record1(sc, (long)saddr, (long)slen, fd, gettid());
}

static inline void
log_sc_exit_with_saddr(u64 sc, char scnm, int scwt, long ret, int flag) {
   // flag=1 means accept, flag=0 means getpeername or recvfrom
   void* saddr;
   long addrlen;
   long fd;
   int slen=0;
   int useful=1;
   int tid = gettid();
   if (arg3_retrieve_and_delete((long*)&saddr, (long*)&addrlen, &fd, tid)) {
      // For syscalls that reach here, it is OK if we don't log error returns
      if (!is_err(ret)) {
         if (useful) {
            if (saddr && addrlen) {
               if (bpf_probe_read((void*)&slen, 4, (void*)addrlen)) {
                  saddr_read_data_err();
                  slen = 0;
               }
            }

            incr_sc_entry(sc);
            if (log_sc_data_long2xt(sc+400, scnm, scwt, saddr, slen, fd, ret))
               saddr_data_err();
         }
      }
#ifdef REPORT_OPEN_ERRS
      else {
         slen = 0;
         incr_sc_entry(sc);
         log_sc_data_long2xt(sc+400, scnm, scwt, saddr, slen, fd, ret);
      }
#endif
   }
}

#ifdef LOG_NET_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
   store_saddr_arg(args->__syscall_nr, WT_ACCEPT, args->upeer_sockaddr, 
                   args->upeer_addrlen, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
   log_sc_exit_with_saddr(args->__syscall_nr,ACCEPT_EX,WT_ACCEPT, args->ret, 1);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
   store_saddr_arg(args->__syscall_nr, WT_ACCEPT, args->upeer_sockaddr, 
                   args->upeer_addrlen, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
   log_sc_exit_with_saddr(args->__syscall_nr,ACCEPT_EX,WT_ACCEPT, args->ret, 1);
   return 0;
}

// We don't log socket, but do cleanup the returned fd.
TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SOCKET)
     log_sc_exit(args->__syscall_nr, SOCKET_EX, args->ret);
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Connect, bind and sendto are similar to the above functions with one       *
 * difference: aockaddr is already known, and is not returned by the syscall. *
 *****************************************************************************/

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
   int fd = (int)args->fd;
   arg3_record1(args->__syscall_nr, (long)args->uservaddr, 
               (long)args->addrlen, fd, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
   void* saddr;
   long addrlen;
   long fd;
   int useful=1;
   if (arg3_retrieve_and_delete((long*)&saddr, &addrlen, &fd, gettid())) {
      u64 id=fd;

      if (useful
#ifndef REPORT_OPEN_ERRS
          && !is_err(args->ret)
#endif
                                 ) {
         incr_sc_entry(args->__syscall_nr);
         if (log_sc_data_long2xt(args->__syscall_nr, CONNECT_EX, WT_CONNECT,
                                 saddr, (int)addrlen, id, args->ret))
            conn_data_err();
      }
   }
   return 0;
}

#ifndef LOG_REP_RDWR
TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
   store_saddr_arg(args->__syscall_nr, WT_GETPEER, args->usockaddr, 
                   args->usockaddr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_getpeername) {
   log_sc_exit_with_saddr(args->__syscall_nr,GETPEER_EX,WT_GETPEER, args->ret,0);
   return 0;
}
#endif

///////////////////////////////////////////////////////////////////////////
// Bind's are rare enough, so OK to log both entry and exit (old scheme)
TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_BIND)
      if (log_sc_data_long1(args->__syscall_nr, BIND_EN, WT_BIND, 
                        args->umyaddr, args->addrlen, args->fd))
         bind_data_err();
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_BIND)
      log_sc_exit(args->__syscall_nr, BIND_EX, args->ret);
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several system calls that are read-like. For reads and writes, we *
 * perform an extra check to prevent loops --- in particular, we skip our own *
 * reads and writes from logging. MY_PID should be the pid of the logging     *
 * process.                                                                   *
 *****************************************************************************/
#ifdef LOG_READ
// We only record the fd and return value for all flavors of read. Other
// arguments, such as the write offset, are being ignored.

static inline void
read_entry(int sc, int fd) {
   int tid = gettid();
   if (tid == MY_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ)
         arg_record1(fd, tid);
}

static inline void
read_entry1(int sc, int scwt, void *addr, void* addr_len, int fd) {
   int tid = gettid();
   if (tid == MY_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ) {
      if (!addr || !addr_len)
         arg_record1(fd, tid);
      else store_saddr_arg(sc, scwt, addr, addr_len, fd);
   }
}

static inline int
read_exit(int sc, int scnm, long ret) {
   long fd; 
   int success = arg_retrieve_and_delete((u64*)&fd, gettid());
   if (success) {
      if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
         incr_sc_entry(sc);
         log_sc_long2xt(sc, scnm, WT_READ, fd, ret);
#endif
      }
      else {
          {
            incr_sc_entry(sc);
            log_sc_long2xt(sc, scnm, WT_READ, fd, ret);
          }
      }
   }
   return success;
}

static inline void
read_exit1(int sc, int scnm, int scwt, long ret) {
   if (!read_exit(sc, READ_EX, ret)) {
      incr_sc_entry(sc);
      log_sc_exit_with_saddr(sc, scnm, scwt, ret, 0);
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmmsg) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv2) {
   read_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
   read_entry1(args->__syscall_nr, WT_RECVFROM, args->addr, args->addr_len,
                   args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_readv) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmmsg) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pread64) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv2) {
   read_exit(args->__syscall_nr, READ_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
   read_exit1(args->__syscall_nr, RECVFROM_EX, WT_RECVFROM, args->ret);
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several system calls that are write-like, and their handling is   *
 * very similar to that of reads.                                             *
 *****************************************************************************/
#ifdef LOG_WRITE
// We only record the fd and return value for all flavors of read. Other
// arguments, such as the write offset, are being ignored.

static inline void
write_entry(int sc, int fd) {
   int tid = gettid();
   if (tid == MY_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE)
      arg_record1(fd, tid);
}

static inline void
write_entry1(int sc, void* addr, int len, int fd) {
   int tid = gettid();
   if (tid == MY_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE) {
      if (!addr || !len) 
         arg_record1(fd, tid);
      else arg3_record1(sc, (long)addr, len, fd, tid);
   }
}

static inline int
write_exit(int sc, int scnm, long ret) {
   long fd; 
   int success = arg_retrieve_and_delete((u64*)&fd, gettid());
   if (success) {
      if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
         incr_sc_entry(sc);
         log_sc_long2xt(sc, scnm, WT_WRITE, fd, ret);
#endif
      }
      else {
          {
            incr_sc_entry(sc);
            log_sc_long2xt(sc, scnm, WT_WRITE, fd, ret);
          }
      }
   }
   return success;
}

static inline void
write_exit1(int sc, int scnm, int scwt, long ret) {
   if (!write_exit(sc, WRITE_EX, ret)) {
      void* saddr;
      long addrlen;
      long fd;
      if (arg3_retrieve_and_delete((long*)&saddr, &addrlen, &fd, gettid())
#ifndef REPORT_RDWR_ERRS
          && !is_err(ret)
#endif
                          ) {
         if (addrlen < 0) addrlen=0;
         incr_sc_entry(sc);
         if (log_sc_data_long2xt(sc, scnm, scwt, saddr, addrlen, fd, ret))
            sendto_data_err();
      }
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev) {
   write_entry(args->__syscall_nr, args->fd);
   return 0; // offset is not an important argument.
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2) {
   write_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
   write_entry1(args->__syscall_nr, args->addr, args->addr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_writev) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmmsg) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev2) {
   write_exit(args->__syscall_nr, WRITE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
   write_exit1(args->__syscall_nr, SENDTO_EX, WT_SENDTO, args->ret);
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Now, onto mmap and mprotect. Only file-backed mmaps are needed to capture  *
 * provenance, so we omit other types of mmaps, UNLESS they set execute perm. *
 * In this case, we record it even if it is not file-backed, since it may be  *
 * used to load or inject code. For mprotect, we only record them if they are *
 * being used for code loading, i.e., have exec perm set.                     *
 *****************************************************************************/
#ifdef LOG_MMAP
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int wt;
   if (ll && ll->log_wt <= WT_MMAP) {
      // Normally, log only if security-relevant: execute permission
      int mmap_imp = (args->prot & PROT_EXEC);

      if (!mmap_imp
#ifdef LOG_MMAPALL 
          && ll->log_wt > WT_MMAPALL
#endif
      )
         return 0;

      long prot = args->prot;
      // encode protection bits the same was as file permissions
      prot = (((prot & PROT_READ) !=0) << 2) |
         (((prot & PROT_WRITE)!=0) << 1) |
         ((prot & PROT_EXEC) !=0);

      if (arg3_record1(args->__syscall_nr, args->start, args->len, prot, gettid()))
         mmap_err();
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mprotect) {
   long start, len, prot;
   if (arg3_retrieve_and_delete(&start, &len, &prot, gettid())
#ifndef REPORT_MMAP_ERRS
       && !is_err(args->ret)
#endif
                            ) {
      incr_sc_entry(args->__syscall_nr);
      log_sc_long3xt(args->__syscall_nr, MPROTECT_EX, WT_MMAP,
                     start, len, (prot << 32) | ((int)args->ret));
   }
   return 0;
}

///////////////////////////////////////////////////////////////////////////////
// mmap has too many arguments, so best to log some at entry and others at exit
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MMAP) {
      int file_backed = ((args->fd >= 0) && !(args->flags & MAP_ANONYMOUS));
      int exec_perm = (args->prot & PROT_EXEC);
      int mmap_imp = file_backed || exec_perm;

      if (!mmap_imp
#ifdef LOG_MMAPALL 
          && ll->log_wt > WT_MMAPALL
#endif
      )
         return 0;

      if (arg_record1(args->fd, gettid()))
         mmap_err();

      long prot = args->prot;
      // encode protection bits the same was as file permissions
      prot = (((prot & PROT_READ) !=0) << 2) |
         (((prot & PROT_WRITE)!=0) << 1) |
         ((prot & PROT_EXEC) !=0);
      long flags = args->flags; // Note: flags has int type

      flags = (flags << 32) | prot;
      log_sc_long3(args->__syscall_nr, MMAP_EN, mmap_imp? WT_MMAP : WT_MMAPALL,
                   args->addr, args->len, flags);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
   int z = 0; u64 fd;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MMAP) {
      if (!arg_retrieve_and_delete(&fd, gettid()))
         return 0;
      log_sc_exit2(args->__syscall_nr, MMAP_EX, (long)fd, args->ret);
   }
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several file-name related syscalls such as link, unlink, symlink, *
 * rename, mkdir, and so on.                                                  *
 *****************************************************************************/

#ifdef LOG_FILENAME_OP
///////////////////////////////////////////////////////////////////////////////
// These are rare enough that we will stick to old scheme (log entry+exit)
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      log_sc_str_long1(args->__syscall_nr, UNLINK_EN, WT_UNLINK,
                    args->pathname, AT_FDCWD);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      log_sc_exit(args->__syscall_nr, UNLINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      log_sc_str_long1(args->__syscall_nr, UNLINK_EN, WT_UNLINK, 
                    args->pathname, args->dfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      log_sc_exit(args->__syscall_nr, UNLINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      log_sc_str_long2(args->__syscall_nr, MKDIR_EN, WT_MKDIR, 
                       args->pathname, AT_FDCWD, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      log_sc_exit(args->__syscall_nr, MKDIR_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      log_sc_str_long2(args->__syscall_nr, MKDIR_EN, WT_MKDIR, 
                       args->pathname, args->dfd, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      log_sc_exit(args->__syscall_nr, MKDIR_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RMDIR)
      log_sc_str_long0(args->__syscall_nr, RMDIR_EN, WT_RMDIR, 
                    args->pathname);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RMDIR)
      log_sc_exit(args->__syscall_nr, RMDIR_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      log_sc_str_long0(args->__syscall_nr, CHDIR_EN, WT_CHDIR, args->filename);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      log_sc_exitt(args->__syscall_nr, CHDIR_EX, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      log_sc_long1(args->__syscall_nr, FCHDIR_EN, WT_CHDIR, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      log_sc_exitt(args->__syscall_nr, FCHDIR_EX, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      log_sc_str2_long3(args->__syscall_nr, LINK_EN, WT_LINK, 
                     args->oldname, args->newname, AT_FDCWD,
                        AT_FDCWD, 0);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      log_sc_exit(args->__syscall_nr, LINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      log_sc_str2_long3(args->__syscall_nr, LINK_EN, WT_LINK, args->oldname, 
                        args->newname, args->olddfd, args->newdfd, 
                        args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      log_sc_exit(args->__syscall_nr, LINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      log_sc_str2_long1(args->__syscall_nr, SYMLINK_EN, WT_SYMLINK, 
                     args->oldname, args->newname, AT_FDCWD);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      log_sc_exit(args->__syscall_nr, SYMLINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      log_sc_str2_long1(args->__syscall_nr, SYMLINK_EN, WT_SYMLINK, 
                     args->oldname, args->newname, args->newdfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      log_sc_exit(args->__syscall_nr, SYMLINK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_str2_long3(args->__syscall_nr, RENAME_EN, WT_RENAME, args->oldname, 
                     args->newname, AT_FDCWD, AT_FDCWD, 0);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_exit(args->__syscall_nr, RENAME_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_str2_long3(args->__syscall_nr, RENAME_EN, WT_RENAME, args->oldname, 
                     args->newname, args->olddfd, args->newdfd, 0);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_exit(args->__syscall_nr, RENAME_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_str2_long3(args->__syscall_nr, RENAME_EN, WT_RENAME,
                     args->oldname, args->newname,
                     args->olddfd, args->newdfd, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      log_sc_exit(args->__syscall_nr, RENAME_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknod)
{
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKNOD)
        log_sc_str_long3(args->__syscall_nr, MKNOD_EN, WT_MKNOD,
                         args->filename, AT_FDCWD, args->mode, args->dev);
   return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_mknod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKNOD)
      log_sc_exit(args->__syscall_nr, MKNOD_EX, args->ret);
   return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      log_sc_str_long3(args->__syscall_nr, MKNOD_EN, WT_MKNOD, 
                       args->filename, args->dfd, args->mode, args->dev);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKNOD)
      log_sc_exit(args->__syscall_nr, MKNOD_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TEE)
      log_sc_long3int(args->__syscall_nr, TEE_EN, WT_TEE, 
                       args->fdin, args->fdout, args->len, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TEE)
      log_sc_exit(args->__syscall_nr, TEE_EX, args->ret);
   return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SPLICE)
      log_sc_long3int(args->__syscall_nr, SPLICE_EN, WT_SPLICE, 
                        args->len, args->fd_in, args->fd_out, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SPLICE)
      log_sc_exit(args->__syscall_nr, SPLICE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_VMSPLICE)
      log_sc_long2(args->__syscall_nr, VMSPLICE_EN, WT_VMSPLICE, 
                         args->fd, args->flags);
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_VMSPLICE)
     log_sc_exit(args->__syscall_nr, VMSPLICE_EX, args->ret);
   return 0;
}


#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several process-related syscalls such as kill, ptrace, and so on. *
 *****************************************************************************/

#ifdef LOG_PROC_CONTROL
///////////////////////////////////////////////////////////////////////////////
// These are important: let us stick to old scheme (log entry+exit), in case 
// the exit is delayed and may impact the logger.
TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      log_sc_long2(args->__syscall_nr, KILL_EN, WT_KILL, 
                   ((args->pid)<<32)|(args->pid), args->sig);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
     log_sc_long2(args->__syscall_nr, KILL_EN, WT_KILL, args->pid, args->sig);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tgkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      log_sc_long2(args->__syscall_nr, KILL_EN, WT_KILL, 
                ((args->tgid)<<32)|args->pid, args->sig);
   return 0;
}

#ifdef LOG_KILL_EXIT
TRACEPOINT_PROBE(syscalls, sys_exit_kill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      log_sc_exit(args->__syscall_nr, KILL_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      log_sc_exit(args->__syscall_nr, KILL_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tgkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      log_sc_exit(args->__syscall_nr, KILL_EX, args->ret);
   return 0;
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE)
      log_sc_long2(args->__syscall_nr, PTRACE_EN, WT_PTRACE, 
                   args->request, args->pid);
   return 0;
}

#ifdef LOG_PTRACE_EXIT
TRACEPOINT_PROBE(syscalls, sys_exit_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE)
      log_sc_exit(args->__syscall_nr, PTRACE_EX, args->ret);
   return 0;
}
#endif
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations to change file permissions.                    *
 *****************************************************************************/

#ifdef LOG_PERM_OP
///////////////////////////////////////////////////////////////////////////////
// These are important (and rare?): let us stick to old scheme (log entry+exit)
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_str_long2(args->__syscall_nr, CHMOD_EN, WT_CHMOD, 
                    args->filename, args->mode, AT_FDCWD);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_exit(args->__syscall_nr, CHMOD_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_long2(args->__syscall_nr, FCHMOD_EN, WT_CHMOD, 
                   args->fd, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_exit(args->__syscall_nr, FCHMOD_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_str_long2(args->__syscall_nr, FCHMOD_EN, WT_CHMOD,
                    args->filename, args->mode, args->dfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      log_sc_exit(args->__syscall_nr, CHMOD_EX, args->ret);
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations related to uid/gid change for processes.       *
 * We encode them all into two operations: setresuid and setresgid.           *
 *****************************************************************************/
///////////////////////////////////////////////////////////////////////////////
// These are important: let us stick to old scheme (log entry+exit)
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_long3(args->__syscall_nr, SETUID_EN, WT_SETUID, 
                args->ruid, args->euid, args->suid);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_long3(args->__syscall_nr, SETUID_EN, WT_SETUID, 
                   args->ruid, args->euid, -1);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_long3(args->__syscall_nr, SETUID_EN, WT_SETUID, -1, args->uid, -1);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_exit(args->__syscall_nr, SETUID_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_exit(args->__syscall_nr, SETUID_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_exit(args->__syscall_nr, SETUID_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_long3(args->__syscall_nr, SETGID_EN, WT_SETGID, 
                args->rgid, args->egid, args->sgid);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_long3(args->__syscall_nr, SETGID_EN, WT_SETGID, 
                   args->rgid, args->egid, -1);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_long3(args->__syscall_nr, SETGID_EN, WT_SETGID, -1, args->gid, -1);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_exit(args->__syscall_nr, SETGID_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_exit(args->__syscall_nr, SETGID_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      log_sc_exit(args->__syscall_nr, SETGID_EX, args->ret);
   return 0;
}
/*******************************************************************************
 * Code added for adding syscall setfsgid, Have used the same Syscall Names and*
 * *****************************************************************************/
TRACEPOINT_PROBE(syscalls, sys_enter_setfsgid) {
    int z = 0;
    struct log_lv *ll = log_level.lookup(&z);
    if (ll && ll->log_wt <= WT_SETGID)
        log_sc_long3(args->__syscall_nr, SETGID_EN, WT_SETGID, -1,args->gid,-1);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_setfsgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_exit(args->__syscall_nr, SETGID_EX, args->ret);
   return 0;
}
/*******************************************************************************
 * Code added for adding syscall setfsuid, Have used the same Syscall Names and*
 ******************************************************************************/
TRACEPOINT_PROBE(syscalls, sys_enter_setfsuid) {
    int z = 0;
    struct log_lv *ll = log_level.lookup(&z);
    if (ll && ll->log_wt <= WT_SETGID)
        log_sc_long3(args->__syscall_nr, SETUID_EN, WT_SETUID, -1,args->uid,-1);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_setfsuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      log_sc_exit(args->__syscall_nr, SETUID_EX, args->ret);
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Process creation and deletion operations. The first group conains fork,    *
 * vfork and clone, while the latter contains exit and exit_group . We record *
 * record some extra information for these syscalls, specifically, uids+gids. *
 * There is also some complication related to the fact that these system      *
 * calls can return in the child before the parent, and if so, we won't know  *
 * who is the parent of the child. This is discussed further later.           *
 *****************************************************************************/

#ifdef LOG_PROC_OP
///////////////////////////////////////////////////////////////////////////////
// These are special, so let us stick to old scheme (log entry+exit)
TRACEPOINT_PROBE(syscalls, sys_enter_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record1(0, gettid());
      log_sc_long0(args->__syscall_nr, FORK_EN, WT_FORK);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record1(0, gettid());
      log_sc_long0(args->__syscall_nr, FORK_EN, WT_FORK);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record1(args->clone_flags, gettid());
      log_sc_long1(args->__syscall_nr, CLONE_EN, WT_FORK, args->clone_flags);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      long flags = 0; // zero is probably a good default
      bpf_probe_read_user(&flags, 8, args->uargs);
      arg_record1(flags, gettid());
      log_sc_long1(args->__syscall_nr, CLONE_EN, WT_FORK, flags);
   }
   return 0;
}

/*
  Note that clone can return in the child before it returns in the parent. Only
  the parent gets the return value as the child pid, and the child does not
  know anything about its parent from the return code of fork/clone. This can
  be inconvenient when processing syscall data, as we will have to process
  data from a child before we have constructed much information about the child,
  such as the parent id, or the file descriptors inherited from the parent.

  Unfortunately, there is no information available at clone exit in the child that
  will *always* tell us the parent of child process/thread. The available
  mechanisms fail as follows:

  1. the cloner can provide a poiner argument such that the kernel writes to
     this memory location before clone returns to child. However, the parent
     may not provide a valid pointer, so the kernel does not store this info
     and hence we cannot access.

  2. We can go to the task struct and ask for the parent process (as shown in
     the code below that is commented out) but if the CLONE_PARENT flag is set,
     the parent will be the parent process of the cloner, and NOT the cloner.

  3. We can rely on the tgid of the cloner and clonee being the same. However,
     if the CLONE_THREAD flag is not set, clonee will go into its own
     thread group, so its tgid will become different from that of the cloner.

  So, it seems that the best option is to avoid trying, and just deal
  with the complications at the user level.
*/

static inline void
log_sc_exit_with_ids(long sc, char scnm, long ret) {
   u64 flags;
   u64 pid_tgid = bpf_get_current_pid_tgid();
   int tid = pid_tgid;
   int pid = pid_tgid >> 32;
   int clone = arg_retrieve_and_delete(&flags, tid);

   if (!is_err(ret) && ((scnm == FORK_EX) || (scnm == CLONE_EX))) {
      if (ret != 0)  {// parent process
         if (clone && (flags & CLONE_THREAD)) {
            if (!(flags & CLONE_FILES)) {
               add_si(pid, 1, 1);
            }
            else add_si(pid, 0, 1);
         }
      }
      else {
         if (tid == pid) // Not a thread, so create subjinfo for the new pid
            add_si(pid, 0, 0);
      }
   }
   // In all other cases, SubjInfo has already been created.

   long uidgid = bpf_get_current_uid_gid();
   long cgroup = bpf_get_current_cgroup_id();
   log_sc_long3xt(sc, scnm, 0, uidgid, cgroup, ret); // wt has been added at entry
}

TRACEPOINT_PROBE(syscalls, sys_exit_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args->__syscall_nr, FORK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args->__syscall_nr, FORK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      log_sc_exit_with_ids(args->__syscall_nr, CLONE_EX, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args->__syscall_nr, CLONE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_exit) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args->__syscall_nr, EXIT_EN, WT_EXIT, args->error_code);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_exit_group) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args->__syscall_nr, EXITGRP_EN, WT_EXIT, args->error_code);
   return 0;
}

/******************************************************************************* 
 *******************************************************************************
 * Finally, execve. It is the most complex of syscalls because of many         *
 * indirectly referenced arguments (argv and env strings). The complexities    *
 * associated with them are discussed further below. There is also another     *
 * difficulty relating to hitting the verifier's limits on code size/number    *
 * of branches in the code. We should solve this problem by using tail calls,  *
 * or better, by putting ourselves in multiple execve-related hooks, and       *
 * splitting up the recording work across these hooks. Some of these hooks     *
 * may also have the advantage that the data is already in kernel memory and   *
 * is hence immune to the errors mentioned below (or race conditions.          *
 ******************************************************************************* 
 * If the parent forks and then uses read-only arguments to execve, reading    *
 * these args in an ebpf probe can result in pagefaults due to lazy copying    *
 * of page tables from parent to child. Since pagefault handlers are disabled  *
 * when executing probes, we get errors. These errors contribute to string,    *
 * argv and data errs below. See the following link for more explanation:      *
 *                                                                             *
https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
 *                                                                             *
 * One work-around suggested is to read the data at the exit of system call.   *
 * I would have thought that the memory has been overwritten by the time       *
 * execve returns. Indeed, the test so far suggests that this is the case, so  *
 * we need to look at other hooks where the data may have been copied over     *
 * from the user level, such as the scheduler's execve, or one of LSM hooks.   *
 ******************************************************************************/
static inline void 
log_execve(int sc, const char* fn, const char* const *argv, 
           const char* const *envp, long fd, long flags) {
   u16 i, hdr; struct buf *b; 
#ifdef LOG_ENV
   char scnm=EXECVEE_EN;
#else
   char scnm=EXECVE_EN;
#endif
   if ((b = init(sc, scnm, WT_EXECVE, &i, &hdr))) {
      add_long2(b, flags, fd, &i, hdr);
      add_string(b, fn, &i);
#ifdef LOG_ENV
      add_str_array0_16(b, argv, &i);
      add_str_array0_16(b, envp, &i);
#else
      // This is the best we have been able to do: increasing array sizes, 
      // even by one, causes verification failure with an unhelpful message
      // "argument list too long." Multiple attempts, such as removing some
      // condition checks etc have yielded no progress. Indeed, typically things
      // get worse. 
      add_str_array0_32(b, argv, &i);
#endif
      finish(b, i);
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
      log_execve(args->__syscall_nr, args->filename, 
                 args->argv, args->envp, AT_FDCWD, 0);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
   long fd = args->fd;

   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
      log_execve(args->__syscall_nr, args->filename, 
              args->argv, args->envp, fd, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
      log_sc_exit_with_ids(args->__syscall_nr, EXECVE_EX, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
      log_sc_exit_with_ids(args->__syscall_nr, EXECVE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_init_module){
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if(ll && ll->log_wt <= WT_IMODULE)
      log_sc_str2_long1(args->__syscall_nr, I_MODULE_EN, WT_IMODULE, 
                            args->uargs,  args->umod, args->len);
      return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_init_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_IMODULE)
      log_sc_exit(args->__syscall_nr, I_MODULE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FIMODULE)
      log_sc_str_long2(args->__syscall_nr, FI_MODULE_EN, WT_FIMODULE, 
                           args->uargs, args->fd, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FIMODULE)
      log_sc_exit(args->__syscall_nr, FI_MODULE_EX, args->ret);
   return 0;
}
#endif
