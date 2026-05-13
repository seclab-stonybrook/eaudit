/*******************************************************************************
 *  Copyright 2022-23 R. Sekar and Secure Systems Lab, Stony Brook University
 *******************************************************************************
 * THIS IS PROPRIETARY SOFTWARE. ALL RIGHTS RESERVED.
 ******************************************************************************/

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// @@@@ When a process is ptraced, or there are similar operations with the
// @@@@ potential to compromise a subject, its versio should be incremented
// @@@@ so that subsequent outflows can be tied to the compromised subject.

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// TODO: Except for special cases where there is too much data (e.g., execve, 
//    mmap) or the risk of delaying a critical event (e.g., ptrace, kill), we
//    should match up entry and exits here. Matching them at the user level isn't
//    100% reliable, as events are buffered and may be delivered out of order.
//    In particular, user level cannot guarantee that the entry and exits of
//    two instances of the same system call are matched up correctly. 
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// The bpfcc toolchain does not seem to envision larger C programs, so the tools
// seem to break any time you try to divide up the source code into multiple
// files and include them. The magic rewrites they do on the C programs seem
// prone to breaking when there are inclusions or macros. 
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// There is also a major fragility in the verifier that causes it to fail
// on inconsequential code changes. This seems related to our extensive use of
// variable size records. Often, our only option is trial and error, involving
// some reordering of unrelated statements. Fortunately, these failures seem
// mostly consistent across Linux kernel versions, so we have to do this just
// once, and not have to maintain different versions for different kernels.

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

#define LOCK_CACHE
#ifdef PERCPU_CACHE
#undef LOCK_CACHE
#undef USE_FLUSH_ALGO_A1
#undef USE_FLUSH_ALGO_A2
#endif

#ifdef TAMPER_DETECT
/*
 * Tamper detection signs records through tail calls. The producer must keep
 * ownership of the cache until signing finishes, so enabling tamper detection
 * must also enable cache locking.
 */
#define LOCK_CACHE
#endif

#define cached_toolong(len, tso, tsc)  (len && tsc >= tso + MAXCACHETIME)
#define cached_far_toolong(len, tso, tsc)  (len && tsc > tso + (3*MAXCACHETIME)/2)

#ifdef ID_NOT_FD
#undef LOG_DUP
#undef LOG_PIPE
#endif

#define mymin(x, y) ((x) < (y) ? (x) : (y))
#define TAILCALL_ADD_ARGV 0
#define TAILCALL_ADD_ENVP 1
#define TAILCALL_UMAC3 2
#define TAILCALL_SIGN_RECORD 3
// We use pid and tid as they are used in userland. (Kernel's tgid becomes
// our pid, while kernel's pid becomes our tid.)
static inline int 
gettid() {
   // Lower 32 bits encode task/thread id
   return bpf_get_current_pid_tgid() & 0xffffffff;
}

static inline int 
getpid() {
   return (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;;
}

static inline u64
gettidpid(int *tid, int *pid) {
   u64 pid_tgid = bpf_get_current_pid_tgid();
   *tid = pid_tgid & 0xffffffff;
   *pid = (pid_tgid >> 32) & 0xffffffff;
   return pid_tgid;
}

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

static inline void open_data_err() { mystat.atomic_increment(OPEN_DATA_ERR); }
static inline void pipe_read_data_err() 
  { mystat.atomic_increment(PIPE_READ_DATA_ERR); }
static inline void saddr_read_data_err() 
  { mystat.atomic_increment(SADDR_READ_DATA_ERR); }
static inline void saddr_data_err() { mystat.atomic_increment(SADDR_DATA_ERR); }
static inline void conn_data_err() { mystat.atomic_increment(CONN_DATA_ERR); }
static inline void sendto_data_err()  { mystat.atomic_increment(SENDTO_DATA_ERR);}
static inline void bind_data_err()  { mystat.atomic_increment(BIND_DATA_ERR);}
static inline void fd_unfound_err(){mystat.atomic_increment(FD_UNFOUND_ERR);}
static inline void file_unfound_err(){mystat.atomic_increment(FILE_UNFOUND_ERR);}
static inline void pipe_unfound_err(){mystat.atomic_increment(PIPE_UNFOUND_ERR);}
static inline void sock_unfound_err(){mystat.atomic_increment(SOCK_UNFOUND_ERR);}
static inline void inode_unfound_err()  
  { mystat.atomic_increment(INODE_UNFOUND_ERR);}

static inline void inc_subj(){mystat.atomic_increment(NUM_SUBJ_CREATED);}
//static inline void inc_obj(){mystat.atomic_increment(NUM_OBJ_CREATED);}

static inline void fdtoid_calls(){mystat.atomic_increment(FDTOID_CALLS);}
static inline void fdtoid_errs(){mystat.atomic_increment(FDTOID_ERRS);}
// indicates that the id became zero. Document why (if?) this matters.

static inline void sc_dropped_lock_contention()
   {mystat.atomic_increment(LOCK_FAIL_LOST_SYSCALLS);}
static inline void unexp_map_lookup_err()
   {mystat.atomic_increment(UNEXP_MAP_LOOKUP_FAIL);}

BPF_HISTOGRAM(cache_flush_lag);
BPF_HISTOGRAM(msg_delivery_lag);

// BPF_HISTOGRAM(fduse);
// BPF_HISTOGRAM(fduset);
static inline void
profile_fd(int fd, int f) {
#ifndef NO_INSTRUMENT
   //if (f == 1)
   //   fduse.increment(bpf_log2l(fd));
   //else fduset.increment(bpf_log2l(fd));
#endif
}

#ifdef NO_INSTRUMENT
#define incr_sc_entry(sc)
#endif

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

/*
   Here are the functions for extra long args
*/
static inline void add_long_full(u8* buf, long v) {
   *(u64*)buf = v;
}

static inline void 
add_long_ex(struct buf* b, long a1, u16* idx) {
   add_long_full(&b->d[*idx], a1);
   *idx += 8;
}

static inline void 
add_long2_ex(struct buf* b, long a1, long a2, u16* idx) {
   add_long_ex(b, a1, idx);
   add_long_ex(b, a2, idx);
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
  if(*idx < BUFSIZE-200){
    int n = bpf_probe_read_str(&b->d[*idx], mymin(MAX_SLEN, BUFSIZE-(*idx)-3),fn);
    // n = max(n, 1);

    if (n < 0) {
     string_err();
     n = 0;
    }
    // Invariant: n >= 0

    if(*idx < BUFSIZE- 200) b->d[*idx-1] = n; // Set str len, incl trailing null
    *idx += n;        // Advance index by string length.
  }     
}

static inline u16
add_str_array0_16(struct buf* b, const char* const *argv, u16 *idx) {

   u8 rv = 0;    
   const char* argarray[16];
   const char** arga = argarray;

   if (bpf_probe_read_user(argarray, sizeof(argarray), argv)) {
      argv_err();
      return 0;
   }

   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #1
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #2
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #3
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #4
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #5
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #6
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #7
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #8
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #9
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #10
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #11
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #12
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #13
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #14
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #15
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #16
   return rv;
}

static inline u16
add_str_array0_32(struct buf* b, const char* const *argv, u16 *idx) {

   u8 rv = 0;    
   const char* argarray[32];
   const char** arga = argarray;

   if (bpf_probe_read_user(argarray, sizeof(argarray), argv)) {
      argv_err();
      return 0;
   }

   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #1
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #2
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #3
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #4
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #5
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #6
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #7
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #8
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #9
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #10
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #11
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #12
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #13
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #14
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #15
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #16
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #17
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #18
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #19
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #20
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #21
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #22
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #23
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #24
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #25
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #26
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #27
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #28
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #29
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #30
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #31
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #32
   return rv;
}

static inline int
add_data(struct buf* b, u8* data, int dlen, u16 *idx) {
   int fail=0;
  u8 len = mymin(MAX_DLEN, dlen);
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
   if(*idx < BUFSIZE-200) b->d[*idx] = len;
   *idx += len+1; // Advance index by length plus space for len field.
   return fail;
}

/****************************************************************************** 
 ******************************************************************************
 * check_xmit1 and check_xmit2 are the only two functions that copy data from
 * the message caches to ring buffer. Both are called by check_xmit, which is in
 * turn called by finish(), the sole function that is called at the end of
 * producing each record. check_xmit1() checks if the cache of the current CPU
 * should be emptied after finishing the record. check_xmit2() is called to
 * empty the cache of another CPU, if that data has been sitting around on that
 * (idle) CPU's cache for too long. It is called by check_xmit(), and the CPU
 * checked is determined by the current sequence number.
 ******************************************************************************/

static inline void check_xmit1(struct buf* b, u16 *i, u64 ts, 
                               int force_tx, int force_wake) {
   if (force_tx || cached_toolong(b->idx, b->start_ts, ts)) {
      u32 rnd = bpf_get_prandom_u32();
      int err=1, flag;
      int sz = mymin(BUFSIZE-1, *i + 8); // Add the size of TSMS record
      if (force_wake || (rnd < (((u32)-1)/RINGBUF_PUSH_INTERVAL)))
         flag = BPF_RB_FORCE_WAKEUP;
      else flag = BPF_RB_NO_WAKEUP;

      mystat.atomic_increment(RB_MSGS);
      if (flag == BPF_RB_FORCE_WAKEUP)
         mystat.atomic_increment(RB_WAKEUPS);
      mystat.atomic_increment(RB_BYTES, *i+8); // # of bytes ATTEMPTED to send

      b->tsrec = TS_RECORD(MS_BITS(b->start_ts));
      // NOTE: we cannot use the reserve/commit API because the verifier
      // requires the size to be a compile-time constant. 

      // The verifier is really finicky on ringbuf access. Unfortunately, the
      // nature of this finickiness changes with the kernel versions. We don't
      // know the exact kernel version to use in the following ifdef
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,12,0)
      //if (sz < BUFSIZE-128)
      if (sz < BUFSIZE-128)
#else
      sz = mymin(sz, BUFSIZE-64);
#endif
         err = events.ringbuf_output(&b->tsrec, sz, flag);

      b->idx = 0;
      b->weight = 0;
      *i = 0;

      if (err)
         mystat.atomic_increment(RB_FAIL);
   }
}

// @@@@ The verifier is very poor at handling copies. When a copy is made,
// @@@@ it does not propagate the known constraints on the values across
// @@@@ copies. This leads to bounds verification failure. Current solution
// @@@@ is trial-and-error to get the compiler and verifier to use the same
// @@@@ register for the bounds checked value and the index. The copy of
// @@@@ check_xmit1 was made to enable this. In the process, we took the
// @@@@ liberty of simplifying away the logic unneeded in the context of xmit2.

static inline void check_xmit2(struct buf* b) {
   int err=1, flag = BPF_RB_FORCE_WAKEUP;
   int sz = mymin(BUFSIZE-1, b->idx+8);
   mystat.atomic_increment(RB_MSGS);
   mystat.atomic_increment(NONLOCAL_CACHE_FLUSHES);
   mystat.atomic_increment(RB_BYTES, b->idx+8); // # of bytes ATTEMPTED to send
   mystat.atomic_increment(RB_WAKEUPS);

   if (sz < (u16)BUFSIZE) { // Always true, but verifier may need help.
         // NOTE: we cannot use the reserve/commit API because the verifier
         // requires the size to be a compile-time constant. 
      b->tsrec = TS_RECORD(MS_BITS(b->start_ts));
      err = events.ringbuf_output(&b->tsrec, sz, flag);
   }            

   b->idx = 0;
   b->weight = 0;

   if (err)
      mystat.atomic_increment(RB_FAIL);
}

static inline void check_xmit3(struct buf* b, u16 *i, u64 ts) {
   if (cached_toolong(b->idx, b->start_ts, ts)
#ifndef FULL_TIME
        || (MS_BITS(b->start_ts) != MS_BITS(ts))
#endif
       )
      check_xmit1(b, i, ts, 1, 0);
}

// Need to define a couple of helpers before check_xmit can be defined

// Cache selection: We need to avoid contention at the cache. The only way
// to do this is by selecting the cache from the CPU id. Other options, such
// as the use of sequence number or thread id's, don't work: two distinct
// sequence numbers (or tids) can hash to the same cache, and hence will
// cause contention. 

static inline int lock_cache_if_needed(struct buf* b, u64 ts) { 
/* returns 1 if lock unnecessary or successfully acquired */
#ifdef LOCK_CACHE 
#ifdef TAMPER_DETECT
  /*
   * Signing may continue through UMAC tail calls, so the producer must own the
   * cache lock for the full record. Otherwise a nonlocal cache flush can copy
   * a partially signed record, or this producer can clear a flusher-owned lock
   * in unlock_cache().
   */
  if (!__sync_fetch_and_add(&b->lock, 1))
    return 1;
  return 0;
#else
   // Lock needed only if tsmsb is too long in the past. Note that the lock is
   // to guard against contention with another core that is cleaning up this
   // core's cache. That cleanup won't be attempted until 1.5*MAXCACHETIME, so
   // it is safe to skip the lock until MAXCACHETIME.
   if (!cached_toolong(b->idx, b->start_ts, ts)) // i.e., lock unnecessary
      return 1;
   if (!__sync_fetch_and_add(&b->lock, 1)) // lock acquired
      return 1;
   else if (b->nargvl > 0) // to avoid lock failure due to tail call getcache
      return 1;
   return 0;
#endif
#else
   return 1;
#endif
}         

// MUST NOT BE CALLED IF YOU DON'T HOLD THE LOCK
static inline void unlock_cache(struct buf* b) {
#ifdef LOCK_CACHE
   b->lock = 0;
#endif
}

static inline void flush_cache(int cpu2check, u64 ts) {
   struct buf* bb = buf.lookup(&cpu2check);
   if (bb && cached_far_toolong(bb->idx, bb->start_ts, ts)) {
      // if (ts - bb->start_ts < 100000000000000ul) // 100K seconds
         cache_flush_lag.increment(bpf_log2l((ts - bb->start_ts)/1000));

      // Note: No need to check that cpu2check isn't this CPU: in that case,
      // cached_far_toolong won't hold because we just called check_xmit1.
      // Triggered only when cpu2check has been idle for a long time, and
      // hence is unlikely to wake simultaneously. So, it is OK to handle
      // lock contention by dropping the syscall. Actually, this happens
      // only for lock fails by cpu2check; and not lock fails of this CPU.
      if (lock_cache_if_needed(bb, ts)) {
         check_xmit2(bb);
         unlock_cache(bb);
      }
      // If we don't get the lock, it must be the case that the core woke
      // up. If it is far_toolong, then too_long() will hold, and so the
      // cache will be emptied by the concerned core. No need for this
      // core to do it.
   }
}

static inline void check_xmit(struct buf* b, u16 *i, int force_tx, int wake) {
   u64 ts = b->current_ts;
   check_xmit1(b, i, ts, force_tx, wake);
              
   // Check if there is data that is stuck for too long on another core's cache.
   // Such a check is possible only if we are using a shared cache.
#ifdef USE_FLUSH_ALGO_A1
   int cpu2check = b->current_sn % NUMCPU;
   flush_cache(cpu2check, ts);
#endif
}

#define LOCKED_INCREMENT
BPF_ARRAY(seqn, u64, 1);    // To assign sequence numbers (if used)
static inline 
u64 getSeqNum() {
      u64 sn=0;
      int z=0;
      u64* snp = seqn.lookup(&z);
      if (snp) {
#ifdef LOCKED_INCREMENT
         sn = __sync_fetch_and_add(snp, 1);
#else
         // A read before AND after seems to reduce the range of possible values,
         // i.e., reduces duplicate sequence numbers. 
         sn = *snp;
         lock_xadd(snp, 1);
         u64 sn1 = *snp;
         if (sn == sn1) // Never true, but the compiler can't figure this out, so
           sn = 0;      // it can't optimize away the second read of *snp.
#endif
      }
      else unexp_map_lookup_err();
      return sn;
}

static inline struct buf*
get_cache(u64 ts) {
   struct buf* b;
   int z = 0;
#ifndef PERCPU_CACHE
   z = bpf_get_smp_processor_id();
#endif

   b = buf.lookup(&z);
   if (!b) {
      unexp_map_lookup_err();
      return b;
   }

#ifndef PERCPU_CACHE
   if (!lock_cache_if_needed(b, ts)) {
      sc_dropped_lock_contention();
      b = NULL;
   }
#endif
   return b;
}

#ifdef USE_FLUSH_ALGO_A2
enum {
  FLUSH_WINDOW_SYSCALL_TOTAL = 0,
  FLUSH_WINDOW_LAST_DAEMON_CHECKPOINT = 1,
};

BPF_ARRAY(syscall_count, u64, 2);

static inline void
record_syscall_for_flush_window() {
  int idx = FLUSH_WINDOW_SYSCALL_TOTAL;
  u64 *ct = syscall_count.lookup(&idx);
  if (ct)
    __sync_fetch_and_add(ct, 1);
  else
    unexp_map_lookup_err();
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Functions for initializing a new event record.                             *
 * init is used to initialize an _entry_ record. It updates the total         *
 * weight of the message (b->weight) but the other helpers don't.             *
 * It calls xmit to copy the per-CPU buffer b into the ring buffer when       *
 * it is too full (idx >= TX_THRESH) or if the MS bits of the timestamp       *
 * has changed from the one in the header of this message.                    *
 ******************************************************************************
 * NOTE: init() copies b->idx into a variable called i or idx, and this       *
 * variable is updated as more params are added to the buffer. Finally,       *
 * finish() copies i back into b->idx.                                        *
 ******************************************************************************/
 
static inline struct buf* 
init(int sc, char scnm, int scwt, u16 *idx, u16 *hdr) {
   u64 ts = bpf_ktime_get_ns(); 
   struct buf* b = get_cache(ts);

   if (sc < 500)
      incr_sc_entry(sc);

#ifdef USE_FLUSH_ALGO_A2
  record_syscall_for_flush_window();
#endif

   if (b) {
      b->current_ts = ts;
      *idx = b->idx;
      u64 sn = getSeqNum();
#ifdef TAMPER_DETECT
    b->current_sn = sn;
#else
      b->current_sn = (u16)sn;
#endif
      if (*idx == 0)
         b->start_ts = ts;
      else if ((*idx > BUFSIZE - 4096)
         // Transmit immediately to ensure (a) enough remaining space in buf,
         // and  (b) TS records are accurate.
#ifndef FULL_TIME
               || (MS_BITS(b->start_ts) != MS_BITS(b->current_ts))
#endif
               )
         {
            check_xmit(b, idx, 1, 0);
            b->start_ts = ts;
         }
    b->current_record_start = *idx;
      b->d[*idx] = scnm; (*idx)++;

#ifdef SHORT_SEQNUM
      *(u16*)(&b->d[*idx]) = (u16)sn; *idx += 2;
#else
#ifdef TAMPER_DETECT
      *(u32*)(&b->d[*idx]) = (u32)(sn & 0x3FFFF);  *idx += 4;
#else
      *(u32*)(&b->d[*idx]) = (u32)sn; *idx += 4;
#endif
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

      int tid, pid;
      u64 pidtid = gettidpid(&tid, &pid);
      if (pid == tid)
         pidtid = pid;
      u8 sz = addLong(&b->d[*idx], pidtid);
      *idx += (1<<sz);
      b->d[*hdr] = (sz<<6);
      b->weight += scwt;
      return b;
   }
   return 0;
}

/******************************************************************************
 * Tamper detection: UMAC3 polynomial-hash MAC with one-time pad.             *
 * MAC(M) = M(poly_key) XOR pad_key, where M(x) is polynomial evaluation.     *
 * Two 32-bit fingerprints (mod P1=2^32-5, mod P2=2^32-17) -> 64-bit MAC.     *
 *                                                                            *
 * tailcall_umac3 processes UMAC3_WORDS_PER_TAIL_CALL words per invocation,   *
 * recursing via BPF tail call for messages longer than 40 bytes.             *
 * On tail-call failure, falls back to emit_record (unsigned) so the buffer   *
 * lock is always released.                                                   *
 ******************************************************************************/
static inline void emit_record(struct buf *b, u16 *i);

static inline void
write_u16_le(struct buf* b, u16 pos, u16 v) {
  if (pos < BUFSIZE - 200) {
    b->d[pos] = (char)(v & 0xff);
    b->d[pos + 1] = (char)((v >> 8) & 0xff);
  }
}

#ifdef TAMPER_DETECT
static inline void
add_signing_key_seed(struct buf* b, const uint64_t seed[2], u16 *idx) {
  *idx += 1;
   if(*idx < BUFSIZE-200){
    int n = bpf_probe_read(&b->d[*idx], sizeof(seed[0]), (const void *)&seed[0]);
    if (n < 0) {
      string_err();
         n = 0;
    }
      n = bpf_probe_read(&b->d[*idx + sizeof(seed[0])], sizeof(seed[1]), (const void *)&seed[1]);
    if (n < 0) {
         string_err();
         n = 0;
    }
      if(*idx < BUFSIZE-200) b->d[*idx - 1] = SIGNING_KEY_SIZE;
      *idx += SIGNING_KEY_SIZE;
   }
}

#define UMAC3_P1 ((1UL << 32) - 5)
#define UMAC3_P2 ((1UL << 32) - 17)
#define UMAC3_WORDS_PER_TAIL_CALL 10

#define UMAC3_FINALIZE_MAC(pad, sp1, sp2)                                      \
  (((pad) ^ (sp1)) ^ (((uint64_t)(sp2)) << 32))

/*
 * Advance the UMAC3 polynomial accumulator by one payload word.
 * Each step reads the next 32-bit chunk, uses the trailing byte count for the
 * final partial word, updates both modular states, and advances the cursor.
 */
#define UMAC3_STEP()                                                           \
  if (remaining >= 1) {                                                        \
    uint32_t _m = read_umac_word((uint8_t *)msg_ptr,                           \
                                 (remaining == 1) ? final_bytes : 0);          \
    uint64_t _x = (uint64_t)sp1 * kp1 + _m;                                    \
    uint64_t _y = (uint64_t)sp2 * kp2 + _m;                                    \
    sp1 = _x % UMAC3_P1;                                                       \
    sp2 = _y % UMAC3_P2;                                                       \
    remaining--;                                                               \
    msg_ptr++;                                                                 \
  }

/*
 * Read a (possibly partial) 32-bit word from the record buffer.
 * bytes_in_word is 0 or 4 for a full word, or 1..3 for the trailing partial
 * word in the final chunk.
 */
static inline uint32_t
read_umac_word(const uint8_t *src, u16 bytes_in_word) {
  uint32_t m = 0;

  if (bytes_in_word == 0 || bytes_in_word == 4) {
    bpf_probe_read(&m, sizeof(m), src);
    return m;
  }

  uint8_t b0 = 0;
  bpf_probe_read(&b0, sizeof(b0), src);
  // m |= b0;
  m = b0;

  if (bytes_in_word >= 2) {
    uint8_t b1 = 0;
    bpf_probe_read(&b1, sizeof(b1), src + 1);
    m |= ((uint32_t)b1) << 8;
  }

  if (bytes_in_word >= 3) {
    uint8_t b2 = 0;
    bpf_probe_read(&b2, sizeof(b2), src + 2);
    m |= ((uint32_t)b2) << 16;
  }

  return m;
}
/* Clear the one-time UMAC keys from the per-record buffer state. */
static inline void umac3_wipe_keys(struct buf *b) {
  b->umac.poly_key = 0;
  b->umac.pad_key = 0;
  b->umac.final_word_bytes = 0;
}

/*
 * Append the signed-record trailer:
 *   - record marker,
 *   - trailer length,
 *   - signed payload length,
 *   - 64-bit MAC.
 */
static inline void
append_mac_trailer(struct buf *b, u16 *idx, uint64_t mac) {
  u16 i = *idx;
  if (i < BUFSIZE - 200 - SIGNED_RECORD_TRAILER_SIZE - 2) {
    b->d[i] = SIGNED_RECORD_MAC_REC;
    b->d[i + 1] = SIGNED_RECORD_TRAILER_SIZE;
    *(u16 *)(&b->d[i + 2]) = b->umac.signed_bytes;
    *(u64 *)(&b->d[i + 2 + SIGNED_RECORD_LEN_SIZE]) = mac;
    *idx = i + 2 + SIGNED_RECORD_LEN_SIZE + SIGNED_RECORD_MAC_SIZE;
  }
}

/*
 * Emit a signed record by appending the MAC trailer, terminating the line,
 * checking transmit thresholds, and releasing the cache lock.
 */
static inline void
emit_signed_record(struct buf *b, u16 *idx, uint64_t mac) {
  append_mac_trailer(b, idx, mac);

  if (*idx < BUFSIZE) {
    b->d[*idx] = '\n';
    *idx = *idx + 1;
  }

  int force_wake = (b->weight >= TX_WT_THRESH);
  int force_tx = force_wake || (*idx >= TX_THRESH);
  check_xmit(b, idx, force_tx, force_wake);
  b->idx = *idx;
  unlock_cache(b);
}

/*
 * tailcall_umac3 resumes UMAC3 signing for a partially built record.
 * It reloads the buffer state, processes up to
 * UMAC3_WORDS_PER_TAIL_CALL payload words in this invocation, and then either
 * tail-calls itself again or finalizes the MAC once the payload has been
 * fully consumed. The bounded batch keeps verifier complexity predictable.
 */
u8
tailcall_umac3(void *ctx) {
  int z = bpf_get_smp_processor_id();
  struct buf *b = buf.lookup(&z);
  if (!b)
    return 0;

  uint32_t sp1 = b->umac.state_p1;
  uint32_t sp2 = b->umac.state_p2;
  int remaining = b->umac.remaining_words;
  uint32_t *msg_ptr = b->umac.msg_words;
  uint64_t kp1 = b->umac.poly_key & 0xffffffff;
  uint64_t kp2 = b->umac.poly_key >> 32;
  u16 final_bytes = b->umac.final_word_bytes;
  u16 *idx = &b->idx;

  /*
   * Expand ten UMAC3_STEP() instances. Each step consumes one payload word and
   * updates both modular accumulators, which keeps the verifier-friendly
   * control flow bounded while still avoiding per-word tail calls.
   */
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP()
  UMAC3_STEP() UMAC3_STEP() UMAC3_STEP()

  /* Persist the updated accumulator state back into the per-CPU buffer. */
  b->umac.state_p1 = sp1;
  b->umac.state_p2 = sp2;
  b->umac.remaining_words = remaining;
  b->umac.msg_words = msg_ptr;

  if (remaining > 0) {
    tailcall.call(ctx, TAILCALL_UMAC3);
    /* Tail call failed: record unsigned fallback. */
    mystat.atomic_increment(SIGN_FAIL_TAILCALL_UMAC_CONT);
    emit_record(b, idx);
    return 0;
  }

  /* All words processed: finalize MAC, wipe keys, emit signed record. */
  uint64_t mac = UMAC3_FINALIZE_MAC(b->umac.pad_key, sp1, sp2);
  umac3_wipe_keys(b);
  emit_signed_record(b, idx, mac);
  return 0;
}

/*******************************************************************************
 * UMAC3: Universal MAC using polynomial fingerprint with one-time pad.
 * MAC(M) = M(umac.poly_key) XOR umac.pad_key, where M(x) = polynomial
 * evaluation mod p. Two 32-bit fingerprints (mod p1=2^32-5, mod p2=2^32-17)
 * concatenated to 64b. umac3_sign seeds the accumulator with the first word,
 * stores the one-time keys in the per-record buffer, and then either finishes
 * immediately for a single-word payload or hands the remaining words to
 * tailcall_umac3. If the tail-call chain cannot continue, the record is
 * emitted unsigned so the cache lock is still released.
 *******************************************************************************/
static inline void
umac3_sign(struct buf *b, void *ctx, int offset,
                              int byte_count, u64 poly_key, u64 pad_key) {
  int word_count = (byte_count + 3) / 4;
  u16 final_bytes = byte_count & 3;

  /* Process first word to seed hash state. */
  uint32_t m = read_umac_word((uint8_t *)(b->d + offset),
                              (word_count == 1) ? final_bytes : 0);
  uint32_t sp1 = m;
  if (sp1 >= UMAC3_P1)
    sp1 -= UMAC3_P1;
  uint32_t sp2 = m;
  if (sp2 >= UMAC3_P2)
    sp2 -= UMAC3_P2;

  b->umac.poly_key = poly_key;
  b->umac.pad_key = pad_key;
  b->umac.final_word_bytes = final_bytes;

  int remaining = word_count - 1;
  if (remaining > 0) {
    /* Delegate remaining words to tail-call chain. */
    b->umac.state_p1 = sp1;
    b->umac.state_p2 = sp2;
    b->umac.msg_words = (uint32_t *)(b->d + offset + 4);
    b->umac.remaining_words = remaining;
    tailcall.call(ctx, TAILCALL_UMAC3);
    /* Tail call failed: emit unsigned. */
    mystat.atomic_increment(SIGN_FAIL_TAILCALL_UMAC_START);
    emit_record(b, &b->idx);
  } else {
    /* Single-word message: compute MAC inline. */
    uint64_t mac = UMAC3_FINALIZE_MAC(pad_key, sp1, sp2);
    umac3_wipe_keys(b);
    emit_signed_record(b, &b->idx, mac);
  }
}
/******************************************************************************
 * Helper functions for tamper detection: key embedding and validation.
 ******************************************************************************/

/*
 * Emit the first signing-key seed once at the start of the stream.
 * This bootstraps parser-side verification and is skipped after the seed has
 * already been embedded.
 */
static inline void
embed_init_key(struct buf *b, u16 *i) {
  int z = 0;
  u16 *embedded = initial_seed_embedded.lookup(&z);
  if (embedded && *embedded == 1)
    return;

  struct signing_key_seed *seed = initial_batch_seed.lookup(&z);
  if (!seed || seed->k[0] == 0)
    return;

  if (*i < BUFSIZE - 200) {
    b->d[*i] = SIGNING_KEY_SEED_REC;
    (*i)++;
  }
  add_signing_key_seed(b, seed->k, i);

  /* Zero the seed after embedding so it cannot be emitted twice. */
  seed->k[0] = 0;
  seed->k[1] = 0;
  u16 flag = 1;
  initial_seed_embedded.update(&z, &flag);
}

/*
 * Emit the next signing-key seed at the batch sync point so the parser and
 * kernel stay aligned with the key-rotation schedule.
 */
static inline void
embed_sync_key(struct buf *b, u16 *i, u64 sn) {
  if (sn % SIGNING_KEY_BATCH_SIZE != SIGNING_KEY_SYNC_POINT - 1)
    return;
  int z = 0;
  struct signing_key_seed *seed = next_batch_seed.lookup(&z);
  if (!seed || seed->k[0] == 0)
    return;

  if (*i < BUFSIZE - 200) {
    b->d[*i] = SIGNING_KEY_SEED_REC;
    (*i)++;
  }
  add_signing_key_seed(b, seed->k, i);
}

#endif

/******************************************************************************
 * emit_record() finalizes an unsigned record, appends the newline, checks
 * transmit thresholds, and releases the cache lock.
 ******************************************************************************/
static inline void
emit_record(struct buf *b, u16 *i) {
  if (b && *i < BUFSIZE - 200) {
    b->d[*i] = '\n';
    (*i)++;
  }
  int force_wake = (b->weight >= TX_WT_THRESH);
  int force_tx = force_wake || (*i >= TX_THRESH);
  check_xmit(b, i, force_tx, force_wake);
  b->idx = *i;
  unlock_cache(b);
}

/*
 * Tail-call target for crypto-aware record finalization. Keeping this as a
 * separate BPF program avoids inlining the signing/key-window logic into large
 * producers such as execve.
 */
u8
tailcall_sign_record(void *ctx) {
#ifdef TAMPER_DETECT
  int cache_key = 0;
#ifndef PERCPU_CACHE
  cache_key = bpf_get_smp_processor_id();
#endif
  int z = 0;
  struct buf *b = buf.lookup(&cache_key);
  if (!b)
    return 0;

  u16 i = b->idx;
  u64 sn = b->current_sn;
  u16 record_start = b->current_record_start;
  u16 payload_bytes = i - record_start;
  payload_bytes = mymin(payload_bytes, MAX_SIGNED_RECORD_BYTES);

  embed_init_key(b, &i);
  embed_sync_key(b, &i, sn);

  b->idx = i;

  u64 *sp = signing_key_window_start.lookup(&z);
  u64 *gep = signing_key_generated_until.lookup(&z);
  if (!sp || !gep)
    goto fail_map_lookup;

  u64 s = *sp;
  u64 gen_end = *gep;

  if (sn < s || sn >= gen_end)
    goto fail_key_window;

  u32 phys_idx = (u32)(sn % SIGNING_KEY_RING_SIZE);
  struct signing_key_batch *ring;
  int local_idx;
  if (phys_idx < SIGNING_KEY_BATCH_SIZE) {
    ring = signing_keys_lo.lookup(&z);
    local_idx = phys_idx;
  } else {
    ring = signing_keys_hi.lookup(&z);
    local_idx = phys_idx - SIGNING_KEY_BATCH_SIZE;
  }
  if (!ring)
    goto fail_map_lookup;
  local_idx = local_idx & (SIGNING_KEY_BATCH_SIZE - 1);

  u64 poly_key = ring->keys[local_idx][0];
  u64 pad_key = ring->keys[local_idx][1];

  u16 *initflag = initial_seed_embedded.lookup(&z);
  if (!initflag || *initflag != 1 || (poly_key == 0 && pad_key == 0))
    goto fail_zero_key;

  ring->keys[local_idx][0] = 0;
  ring->keys[local_idx][1] = 0;

  if (sn == s + SIGNING_KEY_BATCH_SIZE) {
    u64 new_s = s + SIGNING_KEY_HALF_BATCH;
    signing_key_window_start.update(&z, &new_s);
  }

  if (sn == gen_end - SIGNING_KEY_HALF_BATCH - 1) {
    u16 signal =
        (gen_end % SIGNING_KEY_RING_SIZE < SIGNING_KEY_BATCH_SIZE) ? 1 : 2;
    key_refill_request.update(&z, &signal);
  }

  if (payload_bytes > 0 && record_start < i) {
    b->idx = i;
    b->umac.signed_bytes = payload_bytes;
    umac3_sign(b, ctx, record_start, payload_bytes, poly_key, pad_key);
    return 0;
  }

fail_map_lookup:
  mystat.atomic_increment(SIGN_FAIL_MAP_LOOKUP);
  goto fail;
fail_key_window:
  mystat.atomic_increment(SIGN_FAIL_KEY_WINDOW);
  goto fail;
fail_zero_key:
  mystat.atomic_increment(SIGN_FAIL_ZERO_KEY);
  goto fail;
fail:
  emit_record(b, &i);
#endif
  return 0;
}

/******************************************************************************
 * A3 combines A1 (community flushing) and A2 (daemon flushing) but          *
 * suppresses A2 when A1 is already sufficient. This avoids the contention    *
 * caused by running both algorithms on every system call.
 *
 * Idea: Let n be the number of syscalls observed since the last A2 decision. *
 * If n > NUMCPU, then A1 has likely already inspected every CPU within the   *
 * last f milliseconds, so the daemon flush would be redundant. We skip A2    *
 * in that case and advance the checkpoint so the next daemon wake-up starts   *
 * from a fresh window.
 *
 * record_syscall_for_flush_window() increments the global syscall counter.
 * should_skip_daemon_flush() returns 1 when the daemon flush should be skipped
 * because other syscalls have already covered all CPUs; otherwise it returns 0.
 ******************************************************************************/

static inline int
should_skip_daemon_flush() {
#if defined(USE_FLUSH_ALGO_A1) && defined(USE_FLUSH_ALGO_A2)
  int total_idx = FLUSH_WINDOW_SYSCALL_TOTAL;
  int last_idx = FLUSH_WINDOW_LAST_DAEMON_CHECKPOINT;
  u64 *total = syscall_count.lookup(&total_idx);
  u64 *last = syscall_count.lookup(&last_idx);
  if (total && last) {
    u64 since = *total - *last;
    *last = *total;
    if (since > NUMCPU)
      return 1;

  }
  else
    unexp_map_lookup_err();
#endif
  return 0;
}

//#define ADAPTIVE_LATENCY
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
 * occurred at the time of their entry into the kernel.    
 * Finalize a record. With tamper detection enabled, hand the record to a     *
 * dedicated signer program so heavy crypto code does not inflate every syscall*
 * tracepoint program.           
 *****************************************************************************/



static inline void
finish(struct buf *b, u16 i, void *ctx) {
#ifdef TAMPER_DETECT
  b->idx = i;
  tailcall.call(ctx, TAILCALL_SIGN_RECORD);
  mystat.atomic_increment(SIGN_FAIL_TAILCALL_SIGN_RECORD);
#endif
  emit_record(b, &i);
}


/*
 * Tail-call target for the argv phase of execve logging.
 * Index 0 keeps appending argv chunks from the current per-CPU buffer. When
 * argv runs out, the helper either hands off to envp logging (LOG_ENV) or
 * finalizes the execve record immediately (no LOG_ENV).
 */
u8
add_string_tail_argv(void *ctx) {
  u16 *idx;
  u64 ts = bpf_ktime_get_ns(); 
  // struct buf* b = get_cache(ts);
  int z = 0;
#ifndef PERCPU_CACHE
  z = bpf_get_smp_processor_id();
#endif
  struct buf *b = buf.lookup(&z);
   if (b) {
      idx = &b->idx;
      u16 n = add_str_array0_32(b, b->argv , idx);
      b->nargvl += n ;
      //check for more ARGV, if more than continue to tail call until finished
    if (n == 32 && (b->nargvl < (MAX_ARG - 32
#ifdef TAMPER_DETECT
                                 - 256
#endif
                                 ))) {
         b->argv = b->argv + n;
      tailcall.call(ctx, TAILCALL_ADD_ARGV);
      mystat.atomic_increment(EXECVE_TAILCALL_ARGV_CONT_FAIL);
      write_u16_le(b, b->nargpos, b->nargvl);
         b->nargpos = 0;
#ifdef LOG_ENV
      // Fallback: reserve an empty env count if the argv tail call returned.
      write_u16_le(b, *idx, 0);
      *idx += 2;
#endif
      b->nargvl = 0;
      b->nenvpl = 0;
      emit_record(b, idx);
    } else {
      write_u16_le(b, b->nargpos, b->nargvl);
         b->nargpos = 0;
#ifdef LOG_ENV
      tailcall.call(ctx, TAILCALL_ADD_ENVP);
      mystat.atomic_increment(EXECVE_TAILCALL_ENVP_START_FAIL);
      // Fallback: reserve an empty env count if env tail logging is skipped.
      write_u16_le(b, *idx, 0);
      *idx += 2;
      b->nargvl = 0;
      b->nenvpl = 0;
      emit_record(b, idx);
#else
      b->nargvl = 0;
      b->nenvpl = 0;
      finish(b, *idx, ctx);
#endif
      }
   }
   
   return 0;
}

/*
 * Tail-call target for the envp phase of execve logging.
 * This is only used when LOG_ENV is enabled. It appends envp chunks after
 * argv has been fully recorded, then finalizes the record with the combined
 * argv+env payload.
 */
u8
add_string_tail_envp(void *ctx) {
   u16 *idx;
  int z = 0;
#ifndef PERCPU_CACHE
  z = bpf_get_smp_processor_id();
#endif
  struct buf *b = buf.lookup(&z);
   if (b) {
      idx = &b->idx;
    if (b->nenvpl == 0) {
         b->nargpos = *idx;
         *idx += 2;
      }
      u16 n = add_str_array0_32(b, b->envp , idx);
      b->nenvpl += n ;
    u16 env_limit = (b->nargvl < MAX_ARG) ? (MAX_ARG - b->nargvl) : 0;
    if (env_limit > 32 && n == 32 && (b->nenvpl < (env_limit - 32
#ifdef TAMPER_DETECT
                                 - 256
#endif
                                 ))) {
         b->envp = b->envp+n; 
         //tail call itself until finished
      tailcall.call(ctx, TAILCALL_ADD_ENVP);
      mystat.atomic_increment(EXECVE_TAILCALL_ENVP_CONT_FAIL);
      write_u16_le(b, b->nargpos, b->nenvpl);
         b->nargvl = 0;
         b->nenvpl = 0;
      emit_record(b, idx);
    } else {
      write_u16_le(b, b->nargpos, b->nenvpl);
         b->nargvl = 0;
         b->nenvpl = 0;
      finish(b, *idx, ctx);
      }
   }   

   return 0;   
}

/****************************************************************************** 
 ******************************************************************************
 * Higher level marshalling functions. The lower level marshalling functions  *
 * handled a single argument or a single set of arguments. These higher level *
 * functions prepare the complete record: they call one of the init functions *
 * then add all the relevant arguments, and finally call the finish function  *
 * to complete the record. We have several of them below, one for each        *
 * system call entry/exit that is distinct in terms of argument types. Their  *
 * names indicate argument types.                                             *
 *                                                                            *
 * Note that most system calls exits have just a return value to send back to *
 * the user level, so sc_exit() and sc_exitt() are the most frequently used   *
 * for marshalling an exit record. But some system call exits have more data  *
 * return, e.g., an accept system call that returns the information of the    *
 * connected peer. The remaining x() and xt() functions are used for them.    *
 *****************************************************************************/
static inline void 
log_sc_long0(void *ctx, int sc, char scnm, int scwt) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_long1(void *ctx, int sc, char scnm, int scwt, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_long2(void *ctx, int sc, char scnm, int scwt, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_long3(void *ctx, int sc, char scnm, int scwt, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_long4(void *ctx, int sc, char scnm, int scwt, long a1, long a2,
             long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_long5(void *ctx, int sc, char scnm, int scwt, long a1, long a2,
             long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
    finish(b, i, ctx);
   }
}

static inline void 
log_sc_str_long1(void *ctx, int sc, char scnm, int scwt,
                 const char* fn, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      add_string(b, fn, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str_long2(void *ctx, int sc, char scnm, int scwt, const char* fn,
                 long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, fn, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str_long3(void *ctx, int sc, char scnm, int scwt, const char* fn,
                 long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, fn, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str_long4(void *ctx, int sc, char scnm, int scwt,
                 const char* fn, long a1, long a2, long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_string(b, fn, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str_long5(void *ctx, int sc, char scnm, int scwt,
                 const char* fn, long a1, long a2, long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
      add_string(b, fn, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str2_long2(void *ctx, int sc, char scnm, int scwt,
                  const char* s1, const char* s2, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str2_long3(void *ctx, int sc, char scnm, int scwt,
                  const char* s1, const char* s2, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str2_long4(void *ctx, int sc, char scnm, int scwt,
                  const char* s1, const char* s2,
                  long a1, long a2, long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
    finish(b, i, ctx);
   } 
}

static inline void 
log_sc_str2_long5(void *ctx, int sc, char scnm, int scwt,
                  const char* s1, const char* s2,
                  long a1, long a2, long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
    finish(b, i, ctx);
   } 
}

static inline void
log_sc_str3_long2(void *ctx, int sc, char scnm, int scwt,
                  const char *s1, const char *s2,
                  const char *s3, long a1, long a2) {
  u16 i, hdr;
  struct buf *b;
  if ((b = init(sc, scnm, scwt, &i, &hdr))) {
    add_long2(b, a1, a2, &i, hdr);
    add_string(b, s1, &i);
    add_string(b, s2, &i);
    add_string(b, s3, &i);
    finish(b, i, ctx);
  }
}

static inline int
log_sc_data_long2(void *ctx, int sc, char scnm, int scwt,
                  void* data, int len, long a1, long a2) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      fail = add_data(b, data, len, &i);
    finish(b, i, ctx);
   } 
   return fail;
}

static inline int
log_sc_data_long3(void *ctx, int sc, char scnm, int scwt,
                  void* data, int len, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      fail = add_data(b, data, len, &i);
    finish(b, i, ctx);
   } 
   return fail;
}

static inline void unexp_arg_lookup_err(void *ctx, int sc) {
   if (sc < 500 && getpid() != EAUDIT_PID) {
      int z = 0;
      struct log_lv *ll = log_level.lookup(&z);
      if (ll && ll->log_wt <= WT_UNIMPORTANT) {
      log_sc_long2(ctx, sc, ERR_REP, 8, ARG_LOOKUP_ERR, sc);
         mystat.atomic_increment(UNEXP_ARG_LOOKUP_FAIL);
         errcount.atomic_increment(sc);
      }
   }
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

static inline void
arg3_record(long l1, long l2, long l3, int tid) {
   struct long3 info = {l1, l2, l3};
   arg3.update(&tid, &info);
}

static inline int
arg3_retrieve_and_delete(void *ctx, long* l1, long* l2, long* l3, int tid, int sc) {
   struct long3* succ = arg3.lookup(&tid);
   if (succ) {
      *l1 = succ->d1;
      *l2 = succ->d2;
      *l3 = succ->d3;
      arg3.delete(&tid);
      return 1;
   }
   else {
    unexp_arg_lookup_err(ctx, sc);
     return 0;
   }
}

BPF_TABLE("lru_hash", u32, u64, arg, MAX_TASKS); 

static inline void
arg_record(u64 d, int tid) {
   arg.update(&tid, &d);
}

static inline int
arg_retrieve_and_delete(void *ctx, u64* info, int tid, int sc) {
   u64* succ = arg.lookup(&tid);
   if (succ) {
      *info = *succ;
      arg.delete(&tid);
      return 1;
   }
   else {
    unexp_arg_lookup_err(ctx, sc);
      return 0;
   }
}

struct long5 {
   u64 d1;
   u64 d2;
   u64 d3;
   u64 d4;
   u64 d5;
};

BPF_TABLE("lru_hash", u32, struct long5, arg5, MAX_TASKS); 

static inline void
arg5_record(u64 d1, u64 d2, u64 d3, u64 d4, u64 d5, int tid) {
   struct long5 info = {d1, d2, d3, d4, d5};
   arg5.update(&tid, &info);
}

static inline int
arg5_retrieve_and_delete(void *ctx, long* d1, long* d2, long* d3, long* d4,
                         long* d5, int tid, int sc) {
   struct long5* succ = arg5.lookup(&tid);
   if (succ) {
      *d1 = succ->d1;
      *d2 = succ->d2;
      *d3 = succ->d3;
      *d4 = succ->d4;
      *d5 = succ->d5;
      arg5.delete(&tid);
      return 1;
   }
   else {
    unexp_arg_lookup_err(ctx, sc);
      return 0;
   }
}

typedef u64 ObjId;

#ifdef ID_NOT_FD
/****************************************************************************** 
 ****************************************************************************** 
 * Support functions to lookup OS information on file descriptors, and create *
 * 64-bit ids from them. These ids are intended to be collision-resistant     *
 * hashes of the objects referenced by fds. Since we are able to look up the  *
 * info on the OS, we don't have to carefully track the binding of fds or     *
 * their evolution over time. Instead, each log site that needs an id can     *
 * derive it directly from the current fd.                                    *
 *                                                                            *
 * The ids have 2 parts: a 1 to 3 bit object type, plus 61 to 63 bits that    *
 * should provide a collision probability of 1 in 2^60 to 2^62. Valid object  *
 * types include: FILE, PIPE, SELF_NET (sockets for intra-host communication),*
 * and sockets for intranet or internet communication. Collision resistance is*
 * slightly weaker for certain fdtypes, e.g., UNIX domain sockets, as we have *
 * prioritized faster algorithms over collision resistance. For others, e.g., *
 * files, collision resistance is minimized at the cost of somewhat higher    *
 * computational costs.                                                       *
 *****************************************************************************/
static inline ObjId
file2fid(struct file* file, u64 *mtime) {
   struct inode* in = file->f_inode;

   // Inode reuse is fairly common, e.g., on my laptop (ext4), each of the 100
   // distinct files created by the following loop get the same exact inode
   // but a distinct generation. 
   //     for ((i=0; i<100; i++)); do rm -f xx; touch xx; done
   // From the intended purpose of i_generation in the context of NFS, this
   // behavior seems right. I would have expected the generation count to
   // increase sequentially, but perhaps some randomization is being used to
   // defend against some stale handle reuse attacks on NFS? (pure speculation)
   u64 ino = in->i_ino;
   u64 sdev = in->i_sb->s_dev;
   u64 gen = in->i_generation;

   // We use two independent universal hash functions to compute a 32-bit and
   // then a 31-bit hash. Combined into a 63-bit hash, this should give us a
   // collision probability of 1 in 2^63, which is negligible for files on a
   // host. Note that all of the above quantities that feed into the id are
   // 32-bit or less (as of the time this code is written). In fact, the numbers
   // are sufficiently below 2^32 that there is no overflow in the additions
   // involved. (BTW, the added overhead of of the arithmetic operations below
   // is insignificant enough that it is hard to measure.)

   u64 a1 = 2237624219ul; // A random number between 2^31 and 2^32
   u64 a2 = 1336889963ul; // Another random number below 2^32
   u64 p1 = (1ul<<32)-5;  // A prime number less than 2^32
   u64 h1 = (a1*ino + a2*gen) % p1;

   u64 b1 = 3024840434ul; // Another random number below 2^32
   u64 b2 = 2790851613ul; // Another random number below 2^32
   u64 p2 = (1ul<<31)-1;  // A prime less than 2^31
   u64 h2 = (b1*ino + b2*sdev) % p2;

   if (mtime)
      *mtime = in->
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,7,0)
             i_mtime.tv_sec;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(6, 11, 0)
             __i_mtime.tv_sec;
#else
             i_mtime_sec;
#endif

   if (!ino || !sdev) {
      file_unfound_err();
#if (PRINTK_LOG_LEVEL >= 4)
      bpf_trace_printk("file error? ino=%lx dev=%lx gen=%lx", ino, sdev, gen);
#endif
   }
   if (h1==0 || h2==0)
      fdtoid_errs();
   return mkid(FILE_ID, (h2<<32)|h1);
}

static inline ObjId
file2pipeid(struct file* file) {
   struct inode* in = file->f_inode;
   // inodes are created for pipes but perhaps inode numbers are meaningless. In
   // our experiments, we see two successive pipe calls generating the same
   // inode numbers, i.e., 4 fds that have the same i_no. OTOH, there is a
   // pointer i_pipe that stores information about the pipe (such as the
   // buffers, mutextes, etc.) which seems to be reliable: it is shared by the
   // two sides of the pipe, and is not reused until a pipe is closed. (In our
   // tests, i_generation is always zero for pipes.) Ideally, we would like
   // something that does not get reused at all. Our best solution is one that
   // combines the inode and pipe structure pointer.

   u64 ino = in->i_ino; 
   u64 pipe_ptr = (u64)in->i_pipe;
   u64 a = 8975298380752413961ul;
   u64 b = (u64)-6719241545104527607l;
   if (!ino || !pipe_ptr)
      pipe_unfound_err();

   return mkid(PIPE_ID, a*ino + b*(pipe_ptr>>3));
}

// For IP addrs, our id is (meant to be) unique for the 4-tuple (srcip, srcport,
// dstip, dstport) PROVIDED both ends are local to the host. OTHERWISE, our id
// only incorporates remote ip and remote port. This allows us to treat all
// reads of remote IPs as equivalent. For connections between processes on the
// host, the use of 4-tuple ensures that each connection is accurately traced,
// rather than mixing up all the flows involving one of the ends. SECONDLY, for
// remote endpoints, we use current time in deriving the id, allowing the
// trustworthiness of remote endpoints to be different at different times. We
// convert time into an "epoch" by shifting kernel clock (ns) by
// NS_TO_LOCAL_EP_EPOCH bits or NS_TO_FOREIGN_EP_EPOCH bits. (Since we
// accurately trace local endpoints to the right subject at all times, there is
// no need to use time for their ids.)
// @@@@ All of the above made sense at some point. However, our thinking may
// @@@@ evolved on this. The current timestamp epoch policy has made the
// @@@@ rationale for including time in the id less clear. Secondly, getting
// @@@@ local and foreign addresses is
// @@@@ really difficult. Thirdly, the rationale for treating ignoring selfid
// @@@@ is not that strong. At best, it could be an efficiency argument. (Why
// @@@@ reason with distinct connections if they all have same trustworthiness)
// @@@@ But can there be problems? For instance, a spurious propagation of 
// @@@@ provenance between unrelated local processes because they both 
// @@@@ communicated with the same remote host/service? So, it seems best to
// @@@@ disable all this by defining IGNORE_IPADDR_TYPE

#define IGNORE_IPADDR_TYPE

static inline ObjId
inetid2objid(u64 remid, u64 selfid, int kind, int fmly) {
   u64 a = 2897563066638482501ul;
   u64 b = 2348948160164421580ul;
   u64 rv;

#ifdef IGNORE_IPADDR_TYPE
   kind = SELF_NET_ID;
#endif

   if (kind == SELF_NET_ID)
      rv = (remid+a)*(selfid+a);
      // We DON'T want something like a*rem + b*self, as we want to create a 
      // single objid even if rem and self are switched. Addition of (randomly
      // chosen) "a" reduces likelihood that the product will become zero.
   else if (kind == LOCAL_NET_ID) 
      rv = a*(bpf_ktime_get_ns() >> NS_TO_LOCAL_EP_EPOCH) + b*(remid+a);
   else rv = b*(remid+a); 
   // Epoch lengths are different for IP addresses within the enterprise
   
   // Older ID generation taking time into account for remote endpoints: 
   // a*(bpf_ktime_get_ns() >> NS_TO_FOREIGN_EP_EPOCH) + b*(remid+a);
   // Now epoch is taken care of in too_long_time

   if (rv==0) fdtoid_errs();
   return mkid(kind, rv<<2|(fmly != AF_INET));
   // When encoding IP addresses into IDs, we use the least significant two bits
   // for address family, with AF_INET=0, AF_INET6=1, AF_UNIX=2, OTHER=3. (Note
   // that the entire id is shifted left to include FD type --- we are referring
   // to the LS bits before this shift.)
}

#define IPV4LOCALHOST ((127<<24)+1)
static inline int
ip4addrtype(u32 ip) {
   int rv;
   if (ip == INADDR_ANY || ((ip>>24) == 0x7f))
      rv = SELF_NET_ID; 
   else if ((ip & NETMASK1) == NETADDR1 ||
            (ip & NETMASK2) == NETADDR2 ||
            (ip & NETMASK3) == NETADDR3) 
      rv = LOCAL_NET_ID; // %%%% Note: doesn't detect all local addresses.
   else rv = FOREIGN_NET_ID;
   return rv;
}

// @@@@ Fill in the netmask stuff, otherwise every address is considered foreign!
static inline int
ip6addrtype(struct in6_addr* addr) {
   int rv;
   //if ((int)bpf_get_prandom_u32() > 0) // @@@@
   //   rv = SELF_NET_ID;
   // else if ((int)bpf_get_prandom_u32() > (1<<29)) // @@@@
      rv = FOREIGN_NET_ID;
   //else rv = LOCAL_NET_ID;
   return rv;
}

// Unlike v4addr2id, v6addr2id works on just one half of the 4-tuple at a time.
// The caller needs to combine the two halves into one.
static inline ObjId
v6ep2id(struct in6_addr* addr, u32 port) {
   u64 d1 = *(u64*)addr;
   u64 d2 = *((u64*)addr + 1);
   u64 a = 7277111512771247327ul;
   u64 b = 2846993281888046111ul;
   u64 p1 = (1ul<<22)-3;  // Prime numbers to get a 43 bit id
   u64 p2 = (1ul<<21)-9; 
   d1 = a*d1 % p1;
   d2 = b*d2 % p2;
   if (d1==0 || d2==0) fdtoid_errs();
   return (d1<<37)|(((u64)port)<<21)|d2;
}

/* To derive an id from a UNIX domain socket in the abstract name space.   */
static inline ObjId
usock_abs2id(char *n, int len) { 
   // We compute a rolling hash of string p. The hash is a polynomial of the
   // form \sum_{i=0}^{len-1} p[i]*x^i mod N where x is a random number as
   // initialized above. This is the form of Carter-Wegman-Rabin-Karp
   // fingerprinting, with some modifications for efficiency. First is to set N
   // to be 2^64, a suboptimal choice from the perspective of collisions but
   // probably fine because the number of UNIX domain sockets should be
   // relatively small. Second, p isn't a string but a vector of u64s. Third,
   // we only use the first 128 bytes of p.

   u64* p = (u64*)n;
   u64 x = 7892540079625801679ul, rv = 1, t;
   int l = len;

   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 1 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 2 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 3 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 4 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 5 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 6 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 7 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 8 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 9 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*10 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*11 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*12 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*13 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*14 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*15 */
   if (len > 8) len = 8; // truncate if more than 128 bytes

done: /* Invariant: 0 <= len <= 8 */
   t = *p;
   t = t << (8*(8-len)); // @@@@ Correct shift dir for little endian x86
   rv = rv*x + t;

   return rv;
}

static inline ObjId
usock_fn2id(char *n) {
   // Same rolling hash as above, but used for sockets in the file system name
   // space. Two points: (1) We could not reuse the above function, as it 
   // won't get past the verifier in the second use, (2) Perhaps we can count 
   // on this class of UNIX-domain sockets to be present in the file system,
   // and hence use the file-derived id. But I am not sure about some corner
   // cases, e.g., unbound sock. 

   u64 rv=1;
   char s[104];
   u64 x = 7892540079625801679ul, *t, tt;

   int len = bpf_probe_read_str(s, sizeof(s), n);
   int l = len;
   t = (u64*)s; 
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 1 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 2 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 3 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 4 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 5 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 6 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 7 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 8 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 9 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*10 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*11 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*12 */
   if (len > 8) len = 8;

 done:
   if (len > 0) {
      tt = *t;
      tt = tt << (8*(8-len));// @@@@ Correct shift dir for little endian x86
      rv = rv*x + tt; /* 13: max length used is 104 bytes */
   }
   return rv;
}

/* Use the above two functions to compute an id for a UNIX domain socket.     */
/* Also handles the case of unnamed sockets.                                  */
static inline ObjId
usock2id(struct unix_sock* usk, int peer) {
   u64 rv = 1;
   struct unix_address *ua = usk->addr;
   int len = ua? ua->len : 0;
   if (len <= 2) { 
      // There is some complexity involving unbound sockets vs unnamed sockets.
      // Apparently, unbound sockets can have len=0, but unnamed ones should have
      // len=2. Since we don't have any address info in either case, we hope
      // the location of usk won't change during the lifetime of either type
      // of socket. If so, we can use the location of usk as the id. (Note: both
      // are different from abstract sockets (len > 2) handled below.)
      rv = (u64)usk; 
#if (PRINTK_LOG_LEVEL > 4)
      bpf_trace_printk("usock2id unnamed/unbound socket: peer=%d, id=%lx", 
                       peer, rv);
#endif
      return rv;
   }

   struct sockaddr_un *sa = ua->name;
   if (sa->sun_family != AF_UNIX) {
#if (PRINTK_LOG_LEVEL >= 4)
      bpf_trace_printk("usock2id error: sun_family=%d", sa->sun_family);
#endif
      return 0;
   }

   char *n = sa->sun_path;
   if (*n)
     return usock_fn2id(n);
   else return usock_abs2id(n, len);
}

/* Determine socket type, use the right function above to compute an id */
static inline ObjId
file2sockid(struct file* fst) {
   u64 rv=0;
   struct socket* sock = fst->private_data;
   struct sock* sk = sock->sk;
   u16 fmly = sk->sk_family;

   if (fmly == AF_INET || fmly == AF_INET6) {
     struct inet_sock* inetsk = (struct inet_sock *)sk;
     u32 selfport = inetsk->inet_sport;
     selfport = ntohs(selfport);
     u32 remport = inetsk->inet_dport;
     remport = ntohs(remport);
     u32 remid, selfid; int kind;

     if (fmly == AF_INET) { // IP V4
       u32 remip = inetsk->inet_daddr;
       remip = ntohl(remip);
       u32 selfip = inetsk->inet_rcv_saddr;
       selfip = ntohl(selfip);
       if (selfip == INADDR_ANY)
          selfip = inetsk->inet_saddr;

       kind = ip4addrtype(remip);
       remid  = (((u64)remip) <<16) | remport;
       selfid = (((u64)selfip)<<16) | selfport; 
     }

     else { // IP V6
       struct in6_addr remip = sk->sk_v6_daddr;
       struct in6_addr selfip = sk->sk_v6_rcv_saddr;
       if (*(u64*)&selfip == 0 && *((u64*)&selfip + 1) == 0) //INADDR_ANY
          selfip = inetsk->pinet6->saddr;

       kind = ip6addrtype(&remip);
       remid = v6ep2id(&remip, remport);
       selfid = v6ep2id(&selfip, selfport);
     }
     return inetid2objid(remid, selfid, kind, fmly);
   }

   else if (fmly == AF_UNIX) {
     struct unix_sock* usk = (struct unix_sock*)sk;
     struct unix_sock* rusk = (struct unix_sock*)usk->peer;
     rv = usock2id(usk, 0);
     if (rusk)
        rv *= usock2id(rusk, 1);
     if (!rv)
        fdtoid_errs();
     return mkid(SELF_NET_ID, ((rv>>2)<<2)|2);
   }

#if (PRINTK_LOG_LEVEL >= 4)
   if (fmly != 16) // suppress NETLINK socket related errors
      bpf_trace_printk("Unsupported socket family=%d", fmly);
#endif
   return mkid(SELF_NET_ID, 0); // Return some meaningful default
}

/******************************************************************************
 * Top-level function to compute an id from a file descriptor. If mtime is
 * non-null then modification time is filled in for files, dirs and devices.
 ******************************************************************************/
static inline ObjId
fdtoid(int fd, ObjId* mtime) {
   if (mtime) *mtime = 0;
   fdtoid_calls();
   struct task_struct *t = (struct task_struct *)bpf_get_current_task();
   struct files_struct *fst = t->files;
   struct fdtable* fdt = fst->fdt;
   if (fdt && fd < fdt->max_fds) {
      struct file** fds = fdt->fd;
      struct file* file = fds[fd];
      struct inode* in = file->f_inode;
      if (in) {
         u32 mode = in->i_mode;
         if (S_ISREG(mode))
            return file2fid(file, mtime);
         else if (S_ISSOCK(mode))
            return file2sockid(file); // @@@@
         if (S_ISFIFO(mode))
            return file2pipeid(file);
         else if (S_ISDIR(mode) || S_ISLNK(mode))
            return file2fid(file, mtime);
         else /* char or block device */
            return file2fid(file, mtime);
      }
      else inode_unfound_err();
   }
   else fd_unfound_err();
   return mkid(SELF_NET_ID, 0); // Return some meaningful default
}

#endif

#ifdef ID_NOT_FD
static inline u64
proc(long fd) {
   if (fd >= 0)
      return fdtoid(fd, 0);
   return fd;
}
#else
#define proc(x) x
#endif

/*****************************************************************************
 * From here on, we define functions that are directly used by syscall handlers.
 * Basically, logic that will be used in multiple syscall handlers is factored
 * into functions with a similar name, such as store_open_args, log_open_exit,
 * pipe_enter, pipe_exit, etc.
 ****************************************************************************/

static inline void
add_si(u32 pid, int per_thread_fi, int add_thread) {
   inc_subj();
}

static inline void
init_file_fi(int fd, ObjId* data, int dlen) {
   // dlen should be 8 if we don't want file modification time. If dlen == 12
   // then file modification time (32-bits, seconds) is included.
   ObjId *mtime=NULL;
#ifdef USE_MTIME
   if (dlen == 12)
      mtime = (ObjId*)((char*)data + 8);
#endif

#ifdef ID_NOT_FD
   *(u64*)data = fdtoid(fd, mtime);
#endif
}

static inline void
init_pipe_fi(int fd1, ObjId* data) {
#ifdef ID_NOT_FD
   *data = fdtoid(fd1, NULL);
#endif
}

static inline void
store_open_args(const char* fn, int at_fd, int flags, int mode) {
   int wt = (flags & (O_APPEND | O_WRONLY | O_RDWR))? WT_OPENWR : WT_OPENRD;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= wt)
      arg3_record((long)fn, at_fd, ((u64)mode << 32) | flags, gettid());
}

// @@@@ We get too many arg lookup fails for openat (~10%) --- most noticeable
// @@@@ on a short run with firefox on nytimes or washington post. This error is
// @@@@ not seen on longer runs, presumably because the number of opens falls
// @@@@ below 0.2% of syscalls (the threshold for flagging this err) by then.
// @@@@ (Interestingly, firefox causes these errors but chrome doesn't.)
static inline void
log_open_exit(void *ctx, int sc, long ret) {
   char *fn;
   long at_fd;
   long md_flags;

   ObjId data=0;
   if (arg3_retrieve_and_delete(ctx, (long*)&fn, &at_fd, &md_flags, gettid(), sc)) {
      if (!is_err(ret))
         init_file_fi(ret, &data, 8);
#ifndef REPORT_OPEN_ERRS
      else return;
#endif

      int wt = (md_flags & (O_APPEND|O_WRONLY|O_RDWR))? WT_OPENWR : WT_OPENRD;
      log_sc_str_long5(ctx, sc, OPEN_EX, wt, fn, md_flags, at_fd,
                       ret, proc(at_fd),
#ifdef ID_NOT_FD
                       data);
#else
      ret);
#endif
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
pipe_enter(int* fds) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PIPE) {
      arg_record((u64)fds, gettid());
   }
}

static inline void
pipe_exit(void *ctx, int sc, char scnm, long ret) {
   ObjId oid=0;
   int err = is_err(ret);
   int* fdaddr;
   int tid = gettid();

   if (arg_retrieve_and_delete(ctx, (u64*)&fdaddr, tid, sc)) {
      long fds;
      if (!err) {
         if (bpf_probe_read(&fds, 8, fdaddr)) {
            err = 1;
            pipe_read_data_err();
         }
         else ret = fds;
      }

      if (!err)
         init_pipe_fi(ret&0xffffffff, &oid);

      log_sc_long1(ctx, sc, scnm, WT_PIPE, ret);
      // @@@@ Broken when IDs rather than FDs are used. But this is moot
      // since we disable logging of pipe syscall in ID mode.
   }
}

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto the main task: writing the handlers for each system call   *
 * entry and exit. @@@@ TODO: investigate:                                    *
 *                                                                            *
 *   (a) additional tracepoints and/or LSM hooks that can be helpful to track *
 *                                                                            *
 *   (b) or, these points may be more convenient because they operate on data *
 *       that is already in kernel space, and is hence less prone to errors   *
 *       such as pagefaults, or race conditions.                              *
 *                                                                            *
 * We start with functions for opening a file. We record a open as an openat, *
 * adding AT_FDCWD as an extra argument                                       *
 *****************************************************************************/
#ifdef LOG_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
   store_open_args(args->filename, AT_FDCWD, args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open) {
   log_open_exit(args, args->__syscall_nr, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
   store_open_args(args->filename, (int)args->dfd, args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
   log_open_exit(args, args->__syscall_nr, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
   store_open_args(args->pathname,AT_FDCWD,O_CREAT|O_WRONLY|O_TRUNC,args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_creat) {
   log_open_exit(args, args->__syscall_nr, args->ret);
   return 0;
}

///////////////////////////////////////////////////////////////////////////
// We omit oids because our current oid computation requires fds.
TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC) 
      arg3_record((long)args->path, (long)args->length, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC) {
      char* path;
      long length;
      long l3;
      if (arg3_retrieve_and_delete(args, (long*)(&path), &length, &l3, gettid(),
                                   args->__syscall_nr))
         log_sc_str_long2(args, args->__syscall_nr, TRUNC_EX, WT_TRUNC,
                          path, length, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      arg3_record(args->__syscall_nr, args->fd, args->length, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   long fd;
   long length, _ign;
   if (ll && ll->log_wt <= WT_TRUNC
          && arg3_retrieve_and_delete(args, &_ign, &fd, &length, gettid(),
                                      args->__syscall_nr))
      log_sc_long3(args, args->__syscall_nr, FTRUNC_EX, WT_TRUNC,
                   proc(fd), length, (fd << 1) | (args->ret & 0x1));
   return 0;
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
#ifdef LOG_CLOSE
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CLOSE) 
      log_sc_long3(args, args->__syscall_nr, CLOSE_EN, WT_CLOSE, (int)args->fd,
                   0, 0);
#endif
   return 0;
}

// Nothing is lost by leaving out this.
/*
#ifdef LOG_CLOSE  
#ifdef LOG_CLOSE_EXIT
TRACEPOINT_PROBE(syscalls, sys_exit_close) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CLOSE_EX)
      log_sc_exit(args->__syscall_nr, CLOSE_EX, args->ret);
   return 0;
}
#endif
#endif
*/

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto a bunch of functions that change the meaning of file       *
 * descriptors, such as dup. Also included in this group is fcntl, which can  *
 * be used in place of dup. Because fcntl can be very frequent, we only track *
 * fcntl calls with the DUP operation code. The rest are ignored.             *
 *****************************************************************************/
#ifdef LOG_DUP
static inline void
dup_entry(int fd) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_DUP)
      arg_record(fd, gettid());
}

static inline void
dup_exit(void *ctx, int sc, char scnm, int scwt, u64 ret, int errsc) {
   long in_fd;
   int tid = gettid();
   if (arg_retrieve_and_delete(ctx, (u64*)&in_fd, tid, errsc)) {
      int newfd = ret;
      log_sc_long2(ctx, sc, scnm, scwt, in_fd, newfd);
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup) {
   dup_entry(args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup) {
   dup_exit(args, args->__syscall_nr, DUP_EX, WT_DUP,args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
   dup_entry(args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2) {
   dup_exit(args, args->__syscall_nr, DUP2_EX, WT_DUP, args->ret, args->__syscall_nr);
   return 0;
}

// We will record dup2 and dup3 as dup2, ignoring the flag argument of dup3.
TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
   dup_entry(args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup3) {
   dup_exit(args, args->__syscall_nr, DUP2_EX, WT_DUP, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) { // Log only if it is DUP operation
   u64 cmd = args->cmd;
   if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)
      dup_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fcntl) {
   dup_exit(args, args->__syscall_nr, DUP_EX, WT_DUP, args->ret, 600);
   return 0;
}
#endif

#ifdef LOG_PIPE
TRACEPOINT_PROBE(syscalls, sys_enter_pipe) {
   pipe_enter(args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe) {
   pipe_exit(args, args->__syscall_nr, PIPE_EX, args->ret);
   return 0;
}

//@@@@ Protocol info is not being sent. fix.
TRACEPOINT_PROBE(syscalls, sys_enter_socketpair) {
   pipe_enter(args->usockvec);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socketpair) {
   pipe_exit(args, args->__syscall_nr, SOCKPAIR_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pipe2) {
   pipe_enter(args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe2) {
   pipe_exit(args, args->__syscall_nr, PIPE_EX, args->ret);
   return 0;
}

/* Disable: no good reason to support, plus it is not tested through
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SOCKET)
      log_sc_long3(args->__syscall_nr, SOCKET_EN, WT_SOCKET, args->family, 
        args->type, args->protocol);
   return 0;
}
*/
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
store_saddr_arg(int scwt, struct sockaddr* saddr, int* slen, long fd) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= scwt)
     arg3_record((long)saddr, (long)slen, fd, gettid());
}

static inline void
log_sc_exit_with_saddr(void *ctx, int sc, char scnm, int scwt, long ret,
                       int flag, int errsc) {
   // flag=1 means accept, flag=0 means getpeername or recvfrom
   ObjId oid=0;
   void* saddr;
   long alen;
   long fd;
   int slen=0;
   int tid = gettid();
   if (arg3_retrieve_and_delete(ctx, (long*)&saddr, (long*)&alen, &fd, tid, errsc)) {
      // For syscalls that reach here, it is OK if we don't log error returns
      if (!is_err(ret)) {
         if (flag) {
#ifdef ID_NOT_FD
            oid = fdtoid(ret, 0);
#endif
         }
         if (saddr && alen) {
            if (bpf_probe_read((void*)&slen, 4, (void*)alen)) {
               saddr_read_data_err();
               slen = 0;
            }
         }

         if (log_sc_data_long3(ctx, sc, scnm, scwt, saddr, slen, fd, ret,
#ifdef ID_NOT_FD
                                 oid))
#else
                                 fd))
#endif
            saddr_data_err();
      }
#ifdef REPORT_OPEN_ERRS
      else {
         slen = 0;
         log_sc_data_long3(ctx, sc, scnm, scwt, saddr, slen, fd, ret, 0);
      }
#endif
   }
}

#ifdef LOG_NET_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
   store_saddr_arg(WT_ACCEPT, args->upeer_sockaddr, args->upeer_addrlen, 
                   args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, ACCEPT_EX, WT_ACCEPT, args->ret, 1, sc);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
   store_saddr_arg(WT_ACCEPT, args->upeer_sockaddr, args->upeer_addrlen, 
                   args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, ACCEPT_EX, WT_ACCEPT, args->ret, 1, sc);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Connect, bind and sendto are similar to the above functions with one       *
 * difference: aockaddr is already known, and is not returned by the syscall. *
 *****************************************************************************/

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
   int fd = (int)args->fd;
   arg3_record((long)args->uservaddr, (long)args->addrlen, fd, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
   void* saddr;
   long addrlen;
   long fd;
   if (arg3_retrieve_and_delete(args, (long*)&saddr, &addrlen, &fd, gettid(),
                                args->__syscall_nr)) {
      ObjId id=fd; 
      if (!is_err(args->ret)) {
#ifdef ID_NOT_FD
         id = fdtoid(fd, 0);
#endif
      }
#ifndef REPORT_OPEN_ERRS
      if (!is_err(args->ret)) {
#else
      if (1) {
#endif
         if (log_sc_data_long3(args, args->__syscall_nr, CONNECT_EX, WT_CONNECT,
                                 saddr, (int)addrlen, fd, id, args->ret))
            conn_data_err();
      }
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
   store_saddr_arg(WT_GETPEER, args->usockaddr, args->usockaddr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_getpeername) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, GETPEER_EX, WT_GETPEER, args->ret, 0, sc);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_BIND)
      arg3_record((long)args->umyaddr, args->addrlen, args->fd, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   long umyaddr, addrlen, fd;
   if (ll && ll->log_wt <= WT_BIND)
      if (arg3_retrieve_and_delete(args, &umyaddr, &addrlen, &fd, gettid(),
                                   args->__syscall_nr))
         if (log_sc_data_long2(args, args->__syscall_nr, BIND_EX, WT_BIND,
                               (void*)umyaddr, addrlen, fd, args->ret))
                               // fd is not connected to anything so proc(fd)
            bind_data_err();   // is likely useless. Might as well send just fd.
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several system calls that are read-like. They are quite simple to *
 * handle.                                                                    *
 *****************************************************************************/
#ifdef LOG_READ
// We only record the fd and return value for all flavors of read. Other
// arguments, such as the write offset, are being ignored.

static inline void
read_entry(int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ)
         arg_record(fd, tid);
}

static inline void
read_entry1(void *addr, void* addr_len, int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ) {
      if (!addr || !addr_len)
         arg_record(fd, tid);
      else store_saddr_arg(WT_RECVFROM, addr, addr_len, fd);
   }
}

static inline void
log_read(void *ctx, int sc, int scnm, int fd, long ret) {
   if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
      log_sc_long2(ctx, sc, scnm, WT_READ, fd, proc(fd), ret);
#endif
   }
   else {
      log_sc_long3(ctx, sc, scnm, WT_READ, fd, proc(fd), ret);
   }
}

static inline int
read_exit(void *ctx, int sc, int scnm, long ret, int errsc) {
   long fd; 
   int tid = gettid();
   int success = arg_retrieve_and_delete(ctx, (u64*)&fd, tid, errsc);

   if (success) {
      log_read(ctx, sc, scnm, fd, ret);
   }

   return success;
}

static inline void
read_exit1(void *ctx, int sc, int scnm, int scwt, long ret) {
   if (!read_exit(ctx, sc, READ_EX, ret, 600)) // suppress errmsg if arg not found
      log_sc_exit_with_saddr(ctx, sc, scnm, scwt, ret, 0, sc);
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmmsg) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv2) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
   read_entry1(args->addr, args->addr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_readv) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmmsg) {
   read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pread64) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit1(args, args->__syscall_nr, RECVFROM_EX, WT_RECVFROM, args->ret);
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
write_entry(int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE)
      arg_record(fd, tid);
}

static inline void
write_entry1(void* addr, int len, int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE) {
      if (!addr || !len) 
         arg_record(fd, tid);
      else arg3_record((long)addr, len, fd, tid);
   }
}

static inline void
log_write(void *ctx, int sc, int scnm, int fd, long ret) {
   if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
      log_sc_long3(ctx, sc, scnm, WT_WRITE, fd, proc(fd), ret);
#endif
   }
   else {
      log_sc_long3(ctx, sc, scnm, WT_WRITE, fd, proc(fd), ret);
   }
}

static inline int
write_exit(void *ctx, int sc, int scnm, long ret, int errsc) {
   long fd; 
   int tid = gettid();
   int success = arg_retrieve_and_delete(ctx, (u64*)&fd, tid, errsc);
   if (success)
      log_write(ctx, sc, scnm, fd, ret);
   return success;
}

static inline void
write_exit1(void *ctx, int sc, int scnm, int scwt, long ret) {
   if (!write_exit(ctx, sc, WRITE_EX, ret, 600)) { // suppress errmsg if arg unfound
      // Control reaches here on sendto when the socket is not connected. 
      // For unconnected sockets, the peer address is part of the syscall
      // arguments, so reimplement the subset of saddr logging needed here.
      void* saddr;
      long addrlen;
      long fd;
      int tid = gettid();
      if (arg3_retrieve_and_delete(ctx, (long*)&saddr, &addrlen, &fd, tid, sc)
#ifndef REPORT_RDWR_ERRS
          && !is_err(ret)
#endif
                          ) {
         if (addrlen < 0) addrlen=0;
         if (log_sc_data_long2(ctx, sc, scnm, scwt, saddr, addrlen, fd, ret))
                   // fd is unconnected, similar to bind; so send fd, not id.
            sendto_data_err();
      }
   }
}

static inline void sendfile64_entry(int in_fd, int out_fd) {
  int tid = gettid();
  if (getpid() == EAUDIT_PID)
    return;
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_SENDFILE64) {
    long all_fd = (((long)in_fd) << 32) + out_fd;
    arg_record(all_fd, tid);
  }
}

static inline int sendfile64_exit(void *ctx, int sc, int scnm, long ret) {
   u64 all_fd;
   int success = arg_retrieve_and_delete(ctx, &all_fd, gettid(), sc);
   if (success) {
      int in_fd = all_fd >> 32;
      int out_fd = all_fd & ((1l << 32) - 1);
      log_read(ctx, sc, READ_EX, in_fd, ret);
      log_write(ctx, sc, WRITE_EX, out_fd, ret);
   }
   return success;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64) {
  sendfile64_entry(args->in_fd, args->out_fd);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendfile64) {
  sendfile64_exit(args, args->__syscall_nr, READ_EX, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_copy_file_range) {
  sendfile64_entry(args->fd_in, args->fd_out);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_copy_file_range) {
  sendfile64_exit(args, args->__syscall_nr, READ_EX, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev) {
   write_entry(args->fd);
   return 0; // offset is not an important argument.
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
   write_entry1(args->addr, args->addr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_writev) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmmsg) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev2) {
   write_exit(args, args->__syscall_nr, WRITE_EX, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
   write_exit1(args, args->__syscall_nr, SENDTO_EX, WT_SENDTO, args->ret);
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

      arg3_record(args->start, args->len, prot, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mprotect) {
   long start, len, prot;
   if (arg3_retrieve_and_delete(args, &start, &len, &prot, gettid(), 600)
#ifndef REPORT_MMAP_ERRS
       && !is_err(args->ret)
#endif
                            ) {
      log_sc_long3(args, args->__syscall_nr, MPROTECT_EX, WT_MMAP,
                     start, len, (args->ret<<32) | prot);
   }
   return 0;
}

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


      long prot = args->prot;
      // encode protection bits the same was as file permissions
      prot = (((prot & PROT_READ) !=0) << 2) |
         (((prot & PROT_WRITE)!=0) << 1) |
         ((prot & PROT_EXEC) !=0);
      long flags = args->flags; // Note: flags has int type

      flags = (flags << 32) | prot;
      long scwt = mmap_imp? WT_MMAP : WT_MMAPALL;
      arg5_record(scwt, args->addr, args->len, flags, args->fd, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
   int z = 0; 
   long addr, len, flags, scwt, fd;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MMAP) {
      if (!arg5_retrieve_and_delete(args, &scwt,&addr,&len,&flags,&fd, gettid(), 600))
         return 0;
      log_sc_long5(args, args->__syscall_nr, MMAP_EX, scwt, proc((long)fd),
                   addr, len, flags, args->ret);
      // @@@@ We are not sending the fd, only proc(fd). Leaving it that way since
      // @@@@ the chance of mmap on unobserved open is a very rare case.
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
static inline void
log_unlink(void *ctx, int sc, long pathname, long fd, long ret) {
   log_sc_str_long3(ctx, sc, UNLINK_EX, WT_UNLINK, (char*)pathname, fd, proc(fd),
                   ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      arg3_record((long)args->pathname, AT_FDCWD, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, _ign;
   if (ll && ll->log_wt <= WT_UNLINK && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &_ign, gettid(), sc))
      log_unlink(args, sc, pathname, fd, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK)
      arg3_record((long)args->pathname, args->dfd, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, _ign;
   if (ll && ll->log_wt <= WT_UNLINK && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &_ign, gettid(), sc))
      log_unlink(args, sc, pathname, fd, args->ret);
   return 0;
}

static inline void
log_mkdir(void *ctx, int sc, long pathname, long fd, long mode, long ret) {
   log_sc_str_long3(ctx, sc, MKDIR_EX, WT_MKDIR, (char*)pathname, fd, proc(fd),
                    (mode << 32)|(ret&0xffffffff));
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      arg3_record((long)args->pathname, AT_FDCWD, args->mode, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, mode;
   if (ll && ll->log_wt <= WT_MKDIR && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &mode, gettid(), sc))
      log_mkdir(args, sc, pathname, fd, mode, args->ret);
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      arg3_record((long)args->pathname, args->dfd, args->mode, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, mode;
   if (ll && ll->log_wt <= WT_MKDIR && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &mode, gettid(), sc))
      log_mkdir(args, sc, pathname, fd, mode, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RMDIR)
      arg_record((long)args->pathname, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 pathname;
   if (ll && ll->log_wt <= WT_RMDIR && 
         arg_retrieve_and_delete(args, &pathname, gettid(), sc))
      log_sc_str_long1(args, sc, RMDIR_EX, WT_RMDIR, (char*)pathname, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      arg_record((long)args->filename, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 filename;
   if (ll && ll->log_wt <= WT_CHDIR &&
         arg_retrieve_and_delete(args, &filename, gettid(), sc))
      log_sc_str_long1(args, sc, CHDIR_EX, WT_CHDIR, (char*)filename, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR)
      arg_record(args->fd, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
   int z = 0;
   u64 fd;
   int sc = args->__syscall_nr;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt<=WT_CHDIR && arg_retrieve_and_delete(args, &fd,
                        gettid(), sc))
      log_sc_long3(args, sc, FCHDIR_EX, WT_CHDIR, fd, proc(fd), args->ret);
   return 0;
}

static inline void 
log_link(void *ctx, int sc, long oldnm, long newnm, long fd1, long fd2, long fl,
         long ret) {
   log_sc_str2_long5(ctx, sc, LINK_EX, WT_LINK, (char*)oldnm, (char*)newnm, fd1,
                     fd2, (fl<<32)|(ret&0xffffffff), proc(fd1), proc(fd2));
}

TRACEPOINT_PROBE(syscalls, sys_enter_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      arg5_record((u64)args->oldname, (u64)args->newname, AT_FDCWD, 
                  AT_FDCWD, AT_FDCWD, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, fd1, fd2, flag;
   if (ll && ll->log_wt <= WT_LINK && 
       arg5_retrieve_and_delete(args, &oldname,&newname,&fd1,&fd2,&flag, gettid(), sc))
      log_link(args, sc, oldname, newname, fd1, fd2, flag, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK)
      arg5_record((u64)args->oldname, (u64)args->newname, args->olddfd, 
                  args->newdfd, args->flags, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, fd1, fd2, flag;
   if (ll && ll->log_wt <= WT_LINK && 
       arg5_retrieve_and_delete(args, &oldname, &newname,&fd1,&fd2,&flag,gettid(), sc))
      log_link(args, sc, oldname, newname, fd1, fd2, flag, args->ret);
   return 0;
}

static inline void
log_symlink(void *ctx, int sc, long oldname, long newname, long fd, long ret) {
   log_sc_str2_long3(ctx, sc, SYMLINK_EX, WT_SYMLINK, (const char *)oldname,
                     (const char *)newname, fd, proc(fd), ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      arg3_record((long)args->oldname, (long)args->newname, AT_FDCWD, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, dir_fd;
   if (ll && ll->log_wt <= WT_SYMLINK &&
         arg3_retrieve_and_delete(args, &oldname, &newname, &dir_fd, gettid(), sc))
      log_symlink(args, sc, oldname, newname, dir_fd, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK)
      arg3_record((long)args->oldname, (long)args->newname,args->newdfd,gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, dir_fd;
   if (ll && ll->log_wt <= WT_SYMLINK &&
         arg3_retrieve_and_delete(args, &oldname, &newname, &dir_fd, gettid(), sc))
      log_symlink(args, sc, oldname, newname, dir_fd, args->ret);
   return 0;
}

static inline void
log_rename(void *ctx, int sc, long oldnm, long newnm, long ofd, long nfd,
           long fl, long ret) {
   log_sc_str2_long5(ctx, sc, RENAME_EX, WT_RENAME, (const char*)oldnm,
                     (const char*)newnm, ofd, nfd, (fl<<32)|(ret&0xffffffff),
                     proc(ofd), proc(nfd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      arg5_record((long)args->oldname, (long)args->newname, AT_FDCWD, 
                  AT_FDCWD, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
         arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3, gettid(), sc))
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      arg5_record((long)args->oldname, (long)args->newname, args->olddfd, 
                  args->newdfd, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
         arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3,
                                  gettid(), sc))
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME)
      arg5_record((long)args->oldname, (long)args->newname, args->olddfd, 
                  args->newdfd, args->flags, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
         arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3, gettid(), sc))
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   return 0;
}

static inline void
log_mknod(void *ctx, int sc, long filename, long mode, long dev, long fd, long ret) {
   log_sc_str_long4(ctx, sc, MKNOD_EX, WT_MKNOD, (const char*)filename,
                    fd, dev, (mode << 8)|(ret&0xff), proc(fd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknod){
    int z = 0;
    struct log_lv *ll = log_level.lookup(&z);
    if (ll && ll->log_wt <= WT_MKNOD)
      arg3_record((long)args->filename, args->mode, args->dev, gettid());
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dev;
   if (ll && ll->log_wt <= WT_MKNOD &&
       arg3_retrieve_and_delete(args, &filename, &mode, &dev, gettid(), sc))
      log_mknod(args, sc, filename, mode, dev, AT_FDCWD, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR)
      arg3_record((long)args->filename, (args->dfd<<32)|args->mode, 
                  args->dev, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dev;
   if (ll && ll->log_wt <= WT_MKNOD &&
       arg3_retrieve_and_delete(args, &filename, &mode, &dev, gettid(), sc))
      log_mknod(args, sc, filename, mode&0xffffffff, dev, mode>>32, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TEE)
      arg3_record(args->fdin, args->fdout, args->len, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fdin, fdout, len;
   if (ll && ll->log_wt <= WT_TEE &&
       arg3_retrieve_and_delete(args, &fdin, &fdout, &len, gettid(), sc)) {
      log_read(args, sc, READ_EX, fdin, args->ret);
      log_write(args, sc, WRITE_EX, fdout, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_MOUNT)
      arg5_record((long)args->dev_name, (long)args->dir_name, (long)args->type,
                  args->flags, 0, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
  long dev_name, dir_name, type, flags, _ign;
  if (ll && ll->log_wt <= WT_MOUNT &&
      arg5_retrieve_and_delete(args, &dev_name,&dir_name,&type,&flags,&_ign,gettid(),sc))
     log_sc_str3_long2(args, sc, MOUNT_EX, WT_MOUNT, (const char*)dev_name,
                   (const char*)dir_name, (const char*)type, flags, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_umount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_MOUNT)
   arg3_record((long)args->name, args->flags, 0, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_umount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long name, flags, _ign;
  if (ll && ll->log_wt <= WT_MOUNT &&
         arg3_retrieve_and_delete(args, &name, &flags, &_ign, gettid(), sc))
      log_sc_str_long2(args, sc, UMOUNT_EX, WT_MOUNT, (const char*)name,
                       flags, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SPLICE)
      arg3_record(args->len, args->fd_in, args->fd_out, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long len, fd_in, fd_out;
   if (ll && ll->log_wt <= WT_SPLICE &&
       arg3_retrieve_and_delete(args, &len, &fd_in, &fd_out, gettid(), sc)) {
      log_read(args, sc, READ_EX, fd_in, args->ret);
      log_write(args, sc, WRITE_EX, fd_out, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_VMSPLICE)
      arg3_record(args->fd, args->flags, 0, gettid());
      
   return 0;
}

// @@@@ To handle this properly, we need to look up kernel data structures to
// @@@@ determine if this has been opened for read or write, and record as
// @@@@ a read or write.
TRACEPOINT_PROBE(syscalls, sys_exit_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fd, flags, _ign;
   if (ll && ll->log_wt <= WT_VMSPLICE &&
         arg3_retrieve_and_delete(args, &fd, &flags, &_ign, gettid(), sc))
      log_sc_long3(args, sc, VMSPLICE_EX, WT_VMSPLICE, fd, proc(fd), args->ret);
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several process-related syscalls such as kill, ptrace, and so on. *
 *****************************************************************************/

///////////////////////////////////////////////////////////////////////////////
// These are important: let us stick to old scheme (log entry+exit), in case 
// the exit is delayed and may impact the logger.

static inline void 
log_kill_entry(void *ctx, int sc, long pid, int sig) {
   if (sig > 0) {// zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
      arg_record(0, gettid());
      log_sc_long2(ctx, sc, KILL_EN, WT_KILL, pid, sig);
   }
}


TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL) {
#ifdef USE_FLUSH_ALGO_A2
      if (args->sig == 0 && getpid() == EAUDIT_PID) {
      if (!should_skip_daemon_flush()) {
         u64 ts = bpf_ktime_get_ns();
         for (int j=0; j < NUMCPU; j++)
            flush_cache(j, ts);
      }
      }
#endif
      log_kill_entry(args, args->__syscall_nr, args->pid, args->sig);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      if (args->sig > 0) // zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
         log_kill_entry(args, args->__syscall_nr, (args->pid << 32), args->sig);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tgkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      if (args->sig > 0) // zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
         log_kill_entry(args, args->__syscall_nr,
                        ((args->pid)<<32)|args->tgid, args->sig);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_kill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   u64 ignore;
   if (ll && ll->log_wt <= WT_KILL && 
       arg_retrieve_and_delete(args, &ignore, gettid(), 600))
      log_sc_long1(args, 600, KILL_EX, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tkill) {
   int z = 0;
   u64 ignore;
   struct log_lv *ll = log_level.lookup(&z);
   long pid, sig, _ign;
   if (ll && ll->log_wt <= WT_KILL && 
       arg_retrieve_and_delete(args, &ignore, gettid(), 600))
         log_sc_long1(args, 600, KILL_EX, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tgkill) {
   int z = 0;
   u64 ignore;
   struct log_lv *ll = log_level.lookup(&z);
   long pid, sig, _ign;
   if (ll && ll->log_wt <= WT_KILL && 
       arg_retrieve_and_delete(args, &ignore, gettid(), 600))
      log_sc_long1(args, 600, KILL_EX, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE)
      log_sc_long2(args, args->__syscall_nr, PTRACE_EN, WT_PTRACE,
                   args->request, args->pid);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE)
      log_sc_long1(args, 600, PTRACE_EX, 0, args->ret);
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations to change file permissions.                    *
 *****************************************************************************/

#ifdef LOG_PERM_OP
static inline void
log_chmod(void *ctx, int sc, long filename, long fd, long mode, long flags, long ret) {
   log_sc_str_long4(ctx, sc, CHMOD_EX, WT_CHMOD, (const char *)filename,
                    fd, mode, (flags<<8)|ret, proc(fd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      arg3_record((long)args->filename, args->mode, AT_FDCWD, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, fd;
   if (ll && ll->log_wt <= WT_CHMOD &&
         arg3_retrieve_and_delete(args, &filename, &mode, &fd, gettid(), sc))
      log_chmod(args, sc, filename, fd, mode, 0, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD)
      arg3_record((long)args->filename, args->mode, 
         (args->dfd<<32)/*|(args->flag&0xffffffff)*/, gettid());
         // @@@@ flags may be available in a future version. Until then,
         // @@@@ leave this commented out.
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dfd;
   if (ll && ll->log_wt <= WT_CHMOD &&
         arg3_retrieve_and_delete(args, &filename, &mode, &dfd, gettid(), sc))
      log_chmod(args, sc, filename, dfd>>32, mode, dfd&0xffffffff, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FCHMOD)
      arg3_record(args->fd, args->mode, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fd, mode, _ign;
   if (ll && ll->log_wt <= WT_FCHMOD &&
         arg3_retrieve_and_delete(args, &fd, &mode, &_ign, gettid(), sc))
      log_sc_long3(args, sc, FCHMOD_EX, WT_FCHMOD, mode, proc(fd),
                   (fd<<8)|((char)args->ret));
   return 0;
}

static inline void
log_chown(void *ctx, int sc, long fd, long file, long user, long group,
          long fl, long ret) {
   log_sc_str_long5(ctx, sc, CHOWN_EX, WT_CHOWN, (const char*)file, fd, user,
                    group, proc(fd), (fl<<8)|((char)ret));
}


TRACEPOINT_PROBE(syscalls, sys_enter_chown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_CHOWN)
   arg3_record((long)args->filename, args->user, 
               args->group, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  if (ll && ll->log_wt <= WT_CHOWN &&
      arg3_retrieve_and_delete(args, &filename, &user, &group, gettid(), sc))
     log_chown(args, sc, AT_FDCWD, filename, user, group, 0, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_LCHOWN)
   arg3_record((long)args->filename, args->user, args->group, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_lchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  if (ll && ll->log_wt <= WT_LCHOWN &&
         arg3_retrieve_and_delete(args, &filename, &user, &group, gettid(), sc))
   log_chown(args, sc, AT_FDCWD, filename, user, group,AT_SYMLINK_NOFOLLOW,args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchownat) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_CHOWN)
   arg5_record((long)args->filename, (int)args->dfd,
               args->user, args->group, args->flag, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchownat) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  long dfd, flags;
  if (ll && ll->log_wt <= WT_CHOWN &&
      arg5_retrieve_and_delete(args, &filename,&dfd,&user,&group,&flags, gettid(), sc))
     log_chown(args, sc, dfd, filename, user, group, flags, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_FCHOWN)
   arg3_record(args->fd, args->user, args->group, gettid());
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long fd, user, group;
  if (ll && ll->log_wt <= WT_FCHOWN &&
      arg3_retrieve_and_delete(args, &fd, &user, &group, gettid(), sc))
    log_sc_long4(args, sc, FCHOWN_EX, WT_FCHOWN, user, group,
                 (fd<<8)|((char)args->ret), proc(fd));
  return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations related to uid/gid change for processes.       *
 * We encode them all into two operations: setresuid and setresgid.           *
 *****************************************************************************/
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      arg3_record(args->ruid, args->euid, args->suid, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      arg3_record(args->ruid, args->euid, INVAL_UID, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID)
      arg3_record(INVAL_UID, args->uid, INVAL_UID, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long ruid, euid, suid;
   if (ll && ll->log_wt <= WT_SETUID && 
       arg3_retrieve_and_delete(args, &ruid, &euid, &suid, gettid(), sc))
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, ruid, euid, suid, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long ruid, euid, suid;
   if (ll && ll->log_wt <= WT_SETUID &&
         arg3_retrieve_and_delete(args, &ruid, &euid, &suid, gettid(), sc))
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, ruid, euid, suid, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETUID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc))
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, a1, a2, a3, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      arg3_record(args->rgid, args->egid, args->sgid, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      arg3_record(args->rgid, args->egid, INVAL_UID, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID)
      arg3_record(INVAL_UID, args->gid, INVAL_UID, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc))
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, a1, a2, a3, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc))
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, a1, a2, a3, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc))
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, a1, a2, a3, args->ret);
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Process creation and deletion operations. The first group conains fork,    *
 * vfork and clone, while the latter contains exit and exit_group . We record *
 * record some extra information for these syscalls, specifically, uids+gids. *
 *****************************************************************************/

#ifdef LOG_PROC_OP
TRACEPOINT_PROBE(syscalls, sys_enter_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record(0, gettid());
      log_sc_long0(args, args->__syscall_nr, FORK_EN, WT_FORK);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record(0, gettid());
      log_sc_long0(args, args->__syscall_nr, FORK_EN, WT_FORK);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      arg_record(args->clone_flags, gettid());
      log_sc_long1(args, args->__syscall_nr, CLONE_EN, WT_FORK, args->clone_flags);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      long flags = 0; // zero is probably a good default
      bpf_probe_read_user(&flags, 8, args->uargs);
      arg_record(flags, gettid());
      log_sc_long1(args, args->__syscall_nr, CLONE_EN, WT_FORK, flags);
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
  The following options are available to supply the missing information:

  1. the cloner can provide a poiner argument such that the kernel writes to
     this memory location before clone returns to child. However, the parent
     may not provide a valid pointer, so the kernel does not store this info
     and hence we cannot access this info.

  2. We can go to the task struct and ask for the parent process (as shown in
     the code below that is commented out) but if the CLONE_PARENT flag is set,
     the parent will be the parent process of the cloner, and NOT the cloner.
     (It is possible that there are other cases as well, e.g., in the presence
     of a ptrace.)

  3. We can rely on the tgid of the cloner and clonee being the same. However,
     if the CLONE_THREAD flag is not set, clonee will go into its own
     thread group, so its tgid will become different from that of the cloner.

  There seems to be one mechanism to overcome all this, which is to use the
  real_parent field of the task_struct. This field is not well documented, but
  what little information is available suggests that it is exactly what we need.
  We pick it up, and pack it along with the return value, which must be 32-bit
  for fork/exec. 
*/
// Sometimes, clone returns a strange number instead of a thread id. Could
// it be some PID namespace issues? Best to add parent pid info (or 
// something else) to reliably relate parent to child. Alternatively,
// look at the scheduler hook (see examples/ directory here).

static inline void
log_sc_exit_with_ids(void *ctx, long sc, char scnm, long ret) {
   u64 flags=0;
   int tid, pid;
   gettidpid(&tid, &pid);
   int clone = arg_retrieve_and_delete(ctx, &flags, tid, 600);
   int scwt = 0;

   if (!is_err(ret) && ((scnm == FORK_EX) || (scnm == CLONE_EX))) {
      if (ret != 0)  {// parent process
         scwt = WT_CRITICAL;
         if (clone && (flags & CLONE_THREAD)) {
            if (!(flags & CLONE_FILES)) {
               add_si(pid, 1, 1);
            }
            else add_si(pid, 0, 1);
         }
      }
      else {
         scwt = WT_IMPORTANT;
         if (tid == pid) // Not a thread, so count the new pid
            add_si(pid, 0, 0);
      }
   }

   // The fork/clone event emitted below is enough for user-level process state.
   struct task_struct *t = (struct task_struct *)bpf_get_current_task();
   long parent_tid = t->real_parent->pid;
   ret = (ret & 0xffffffff) | (parent_tid << 32);

   // bpf_get_current_uid_gid() returns real userid. Who needs that?
   // So we need to navigate task_struct get the effective uid/gid
   u64 uidgid = t->cred->egid.val;
   uidgid = (uidgid << 32) | t->cred->euid.val;

   long cgroup = bpf_get_current_cgroup_id();
   log_sc_long3(ctx, 600, scnm, scwt, uidgid, cgroup, ret);
   // Previously, weight was zero, but this can cause long delays for the
   // exit event to get to the user level. This can lead to errors in
   // matching fork entries and exits, which, in turn, has the potential
   // for misattribution or mishandling of syscalls.
}

TRACEPOINT_PROBE(syscalls, sys_exit_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, FORK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, FORK_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      log_sc_exit_with_ids(args, args->__syscall_nr, CLONE_EX, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, CLONE_EX, args->ret);
   return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_exit) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args, args->__syscall_nr, EXIT_EN, WT_EXIT, args->error_code);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_exit_group) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args, args->__syscall_nr, EXITGRP_EN, WT_EXIT, args->error_code);
   return 0;
}


/******************************************************************************* 
 *******************************************************************************
 * Finally, execve. It is the most complex of syscalls because of many         *
 * indirectly referenced arguments (argv and env strings). The complexities    *
 * associated with them are discussed further below. There is also another     *
 * difficulty relating to hitting the verifier's limits on code size/number    *
 * of branches in the code. We have solved this using tail calls               *
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
/*
 * log_execve builds the entry-side execve/execveat record.
 *
 * Flow:
 *   1. Emit the common syscall header and the pathname / metadata.
 *   2. Reserve space for the argv count, then copy the first 16 argv entries.
 *   3. If more argv remain, store the cursor in the per-CPU buffer and
 *      tail-call into add_string_tail_argv() to continue in bounded chunks.
 *   4. When LOG_ENV is enabled, the argv tail helper hands off to
 *      add_string_tail_envp() so envp is appended after argv.
 *   5. When env logging is disabled, the argv tail helper finalizes the
 *      record immediately after argv is complete.
 *
 * The per-CPU cache lock taken by init() stays owned across the tail-call
 * chain and is released only by finish()/emit_record() at the end of the
 * flow.
 */
static inline void 
log_execve(void *ctx, int sc, const char* fn, const char* const *argv, 
           const char* const *envp, long fd, long flags) {
   u16 i, hdr; struct buf *b; 
#ifdef LOG_ENV
   char scnm=EXECVEE_EN;
#else
   char scnm=EXECVE_EN;
#endif
   if ((b = init(sc, scnm, WT_EXECVE, &i, &hdr))) {
      add_long3(b, flags, fd, proc(fd), &i, hdr);
      add_string(b, fn, &i);
      b->nargpos = i;
      i += 2;
      u16 argv_count = add_str_array0_16(b, argv, &i);
      b->nargvl = argv_count;
    write_u16_le(b, b->nargpos, b->nargvl);

    if (argv_count < 16) {
#ifdef LOG_ENV
      b->idx = i;
      b->envp = envp;
      tailcall.call(ctx, TAILCALL_ADD_ENVP);
      mystat.atomic_increment(EXECVE_TAILCALL_ENVP_START_FAIL);
      // Fallback: a zero env count keeps the parser aligned if tail call fails.
      write_u16_le(b, i, 0);
      i += 2;
      finish(b, i, ctx);
#else
      b->nargvl = 0;
      b->nenvpl = 0;
      finish(b, i, ctx);
#endif
      return;
      }

      b->idx = i;
    b->argv = argv + argv_count; // Continue with the next argv chunk.
#ifdef LOG_ENV
      b->envp = envp;
#endif
    tailcall.call(ctx, TAILCALL_ADD_ARGV);
    mystat.atomic_increment(EXECVE_TAILCALL_ARGV_START_FAIL);
    
#ifdef LOG_ENV
         b->idx = i;
    write_u16_le(b, b->nargpos, b->nargvl);
         b->envp = envp;
    tailcall.call(ctx, TAILCALL_ADD_ENVP);
    mystat.atomic_increment(EXECVE_TAILCALL_ENVP_START_FAIL);
    // Fallback: keep the env field present even if the env tail call returns.
    write_u16_le(b, i, 0);
    i += 2;
    finish(b, i, ctx);
#else
    write_u16_le(b, b->nargpos, b->nargvl);
    b->nargvl = 0;
    b->nenvpl = 0;
    finish(b, i, ctx);
#endif
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   // u64 pidtid = bpf_get_current_pid_tgid(); 
   // u64 fn = (u64)args->filename;
   // execve.update(&pidtid, &fn);

   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
    log_execve(args, args->__syscall_nr, args->filename, args->argv, args->envp,
               AT_FDCWD, 0);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
   int z = 0;
   long fd = proc(args->fd);
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
    log_execve(args, args->__syscall_nr, args->filename, args->argv, args->envp,
               fd, args->flags);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
    log_sc_exit_with_ids(args, args->__syscall_nr, EXECVE_EX, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE)
    log_sc_exit_with_ids(args, args->__syscall_nr, EXECVE_EX, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_init_module){
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if(ll && ll->log_wt <= WT_INITMOD)
      arg_record((long)args->uargs, gettid());
      return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_init_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 uargs;
   if (ll && ll->log_wt <= WT_INITMOD &&
      arg_retrieve_and_delete(args, &uargs, gettid(), sc))
    log_sc_str_long1(args, sc, INITMOD_EX, WT_INITMOD,
                     (const char *)uargs, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FINITMOD)
    arg3_record((long)args->uargs, args->fd, args->flags, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long uargs, fd, flags;
   if (ll && ll->log_wt <= WT_FINITMOD && 
      arg3_retrieve_and_delete(args, &uargs, &fd, &flags, gettid(), sc))
    log_sc_str_long4(args, sc, FINITMOD_EX, WT_FINITMOD, (const char *)uargs,
                       fd, flags, args->ret, proc(fd));
   return 0;
}
#endif
