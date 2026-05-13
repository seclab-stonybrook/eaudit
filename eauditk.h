#ifndef EAUDITK_H
#define EAUDITK_H

#define MAX_SLEN 128 // Max size of string argument fetched from process memory
#define MAX_DLEN 128 // Max size of data arguments fetched from process memory
#define MAX_ARG 512 // 576 // Max arguments that can be logged in execve syscall
// #define BUFSIZE 2 * TX_THRESH + 223 * MAX_DLEN // Shd be big enough for
// execve
#define BUFSIZE (16 * 1024 - 128) // This size ensures that the total cache size
// will be <= 16K. This 16K bounds also limits max complexity of execve logging.

#define SIGNING_KEY_BATCH_SIZE 131072UL
#define SIGNING_KEY_RING_SIZE (2 * SIGNING_KEY_BATCH_SIZE)
#define SIGNING_KEY_HALF_BATCH (SIGNING_KEY_BATCH_SIZE / 2)
#define SIGNING_KEY_SYNC_POINT                                                 \
  (3 * SIGNING_KEY_BATCH_SIZE /                                                \
   4) // Embed next batch seed here (75% through batch)
#define SIGNING_KEY_SIZE 16
#define SIGNED_RECORD_LEN_SIZE 2
#define SIGNED_RECORD_MAC_SIZE 8
#define SIGNED_RECORD_TRAILER_SIZE                                             \
  (SIGNED_RECORD_LEN_SIZE + SIGNED_RECORD_MAC_SIZE)
#define MAX_SIGNED_RECORD_BYTES 712

/*******************************************************************************
 * Maps that can be queried by the user level to determine status and stats *
 ********************************************************************************/
enum StatIdx {
  RB_FAIL = 0,
  RB_BYTES = 1,
  RB_MSGS = 2,
  RB_WAKEUPS = 3,
  FN_ERR = 4,
  DATA_ERR = 5,
  ARGV_ERR = 6,
  FCNTL_ERR = 7,
  SADDR_ERR = 8,
  PIPE_ERR = 9,
  MMAP_ERR = 10,
  UNUSED_STAT_11 = 11,
  UNUSED_STAT_12 = 12,
  FN_TRUNC_ERR = 13,
  DATA_TRUNC_ERR = 14,
  DATA_READ_OK = 15,
  OPEN_DATA_ERR = 16,
  SADDR_DATA_ERR = 17,
  CONN_DATA_ERR = 18,
  SENDTO_DATA_ERR = 19,
  BIND_DATA_ERR = 20,
  PIPE_READ_DATA_ERR = 21,
  SADDR_READ_DATA_ERR = 22,
  FD_UNFOUND_ERR = 23,
  INODE_UNFOUND_ERR = 24,
  FILE_UNFOUND_ERR = 25,
  PIPE_UNFOUND_ERR = 26,
  SOCK_UNFOUND_ERR = 27,
  FDTOID_ERRS = 28,
  FDTOID_CALLS = 29,
  UNUSED_STAT_30 = 30,
  UNUSED_STAT_31 = 31,
  UNUSED_STAT_32 = 32,
  UNUSED_STAT_33 = 33,
  NUM_SUBJ_CREATED = 34,
  UNUSED_STAT_35 = 35,
  UNUSED_STAT_36 = 36,
  UNUSED_STAT_37 = 37,
  UNUSED_STAT_38 = 38,
  UNUSED_STAT_39 = 39,
  UNUSED_STAT_40 = 40,
  UNUSED_STAT_41 = 41,
  UNUSED_STAT_42 = 42,
  UNUSED_STAT_43 = 43,
  UNUSED_STAT_44 = 44,
  UNUSED_STAT_45 = 45,
  UNUSED_STAT_46 = 46,
  UNUSED_STAT_47 = 47,
  LOCK_FAIL_LOST_SYSCALLS = 48,
  UNEXP_MAP_LOOKUP_FAIL = 49,
  UNEXP_ARG_LOOKUP_FAIL = 50,
  NONLOCAL_CACHE_FLUSHES = 51,
  NONLOCAL_CACHE_CHECKS = 52,
  UNUSED_STAT_53 = 53,
  UNUSED_STAT_54 = 54,
  UNUSED_STAT_55 = 55,
  UNUSED_STAT_56 = 56,
  UNUSED_STAT_57 = 57,
  SIGN_FAIL = 58,
  SIGN_FAIL_KEY_WINDOW = 59,
  SIGN_FAIL_ZERO_KEY = 60,
  SIGN_FAIL_TAILCALL_SIGN_RECORD = 61,
  SIGN_FAIL_MAP_LOOKUP = 62,
  SIGN_FAIL_TAILCALL_UMAC_START = 63,
  SIGN_FAIL_TAILCALL_UMAC_CONT = 64,
  EXECVE_TAILCALL_ARGV_START_FAIL = 65,
  EXECVE_TAILCALL_ARGV_CONT_FAIL = 66,
  EXECVE_TAILCALL_ENVP_START_FAIL = 67,
  EXECVE_TAILCALL_ENVP_CONT_FAIL = 68,
  MAX_STAT = 69
};

// Dynamic congestion control: setting log_wt to w will cause syscalls with
// weights < w to be dropped. See further down for syscall weights.

#ifdef __KERNEL__
struct log_lv {
  u32 log_wt;
};

struct umac_info {
  u32 *msg_words;       // next 32-bit message word for tail-call processing
  u32 state_p1;         // running fingerprint value (mod p1)
  u32 state_p2;         // running fingerprint value (mod p2)
  u64 poly_key;         // polynomial/fingerprint key
  u64 pad_key;          // one-time pad key
  u16 remaining_words;  // remaining 32-bit words to process
  u16 signed_bytes;     // signed payload length stored in trailer
  u16 final_word_bytes; // bytes in final partial word, 0 if full
};

struct buf {
  u16 idx;
  u16 current_record_start;
  u16 nargvl;
  u16 nenvpl;
  u16 nargpos;
  u64 current_sn;
  u32 weight;
  const char *const *envp;
  const char *const *argv;
  struct umac_info umac;
  u64 current_ts;
  u64 lock;
  u64 start_ts;
  u64 tsrec;       // No fields between tsrec and d: tsrec to d[idx] transmitted
  char d[BUFSIZE]; // to user level, so such fields will corrupt the message.
};

struct adaptive_latency {
  int qlen;
  int prev_qlen;
  // add other needed fields.
};

struct signing_key_batch {
  u64 keys[SIGNING_KEY_BATCH_SIZE][2];
};

struct signing_key_seed {
  u64 k[2];
};

BPF_ARRAY(msgs_rcvd, long, 1);
BPF_ARRAY(tx_fac, u32, 1);
BPF_ARRAY(mystat, u64, MAX_STAT);
BPF_ARRAY(log_level, struct log_lv, 1); // For dynamic control of events to log
BPF_ARRAY(count, u64, 400);             // To track # of system call entries
BPF_ARRAY(errcount, u64, 400); // # arg retrieval error for each syscall
BPF_ARRAY(countexit, u64, 1);  // To track # combined system call exits
BPF_PROG_ARRAY(tailcall, 33);  // For storing key value pair for tail call

#ifdef TAMPER_DETECT
// This creates a circular queue of one-time UMAC keys with logical slots
// [0, 2 * SIGNING_KEY_BATCH_SIZE). Each record uses the slot
// sn % SIGNING_KEY_RING_SIZE, so sequence numbers wrap around the same two-batch
// key ring. Slots [0, SIGNING_KEY_BATCH_SIZE) live in signing_keys_lo, and slots
// [SIGNING_KEY_BATCH_SIZE, SIGNING_KEY_RING_SIZE) live in signing_keys_hi after
// subtracting SIGNING_KEY_BATCH_SIZE.
//
// Keeping two batches lets eBPF consume one half while userspace prepares the
// other half. The ring is split into lo/hi maps because putting the full two-
// batch key ring in one map value would be too large for practical BPF map use.
//
// The seed maps serve the log-verification path, not the hot signing lookup.
// initial_batch_seed is embedded once so the parser can derive the first batch;
// next_batch_seed is embedded at each sync point so the parser can derive the
// following batch.
//
// key_refill_request is the kernel-to-userspace signal that says which half of
// the ring has become safe to overwrite. signing_key_window_start marks the
// oldest key eBPF still accepts, while signing_key_generated_until marks the
// first sequence number for which userspace has not generated a key yet.
BPF_ARRAY(signing_keys_lo, struct signing_key_batch,
          1); // keys [0, SIGNING_KEY_BATCH_SIZE)
BPF_ARRAY(signing_keys_hi, struct signing_key_batch,
          1); // keys [SIGNING_KEY_BATCH_SIZE, SIGNING_KEY_RING_SIZE)
BPF_ARRAY(next_batch_seed, struct signing_key_seed,
          1); // seed for the next generated batch
BPF_ARRAY(initial_batch_seed, struct signing_key_seed,
          1);                          // first batch seed, embedded once
BPF_ARRAY(key_refill_request, u16, 1); // signal userspace: 1=fill lo, 2=fill hi
BPF_ARRAY(initial_seed_embedded, u16,
          1); // set after initial seed is embedded in the log
BPF_ARRAY(signing_key_window_start, u64,
          1); // first valid sequence number in the key ring
BPF_ARRAY(signing_key_generated_until, u64,
          1); // first sequence number without a generated key
#endif

#ifdef PERCPU_CACHE
BPF_PERCPU_ARRAY(buf, struct buf, 1);
#else
BPF_ARRAY(buf, struct buf, NUMCPU + 1);
#endif

BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);
#endif
/******************************************************************************
 * Weights of various system calls are specified below. They refer to constant *
 * values defined in the Python program that includes/compiles this program. *
 ******************************************************************************/
/*************** Privilege escalation and process interference ***************/
#define WT_EXECVE WT_CRITICAL
#define WT_SETUID WT_CRITICAL
#define WT_KILL WT_CRITICAL
#define WT_PTRACE WT_CRITICAL
#define WT_FINITMOD WT_CRITICAL
#define WT_INITMOD WT_CRITICAL
#define WT_MOUNT WT_CRITICAL
#define WT_FORK WT_CRITICAL // Changed from IMPORTANT so as to minimize the
// likelihood of errors in matching entries and exits. Such errors can cause
// misattribution of syscalls and other potential problems.

/********************** Process provenance and loading ***********************/
#define WT_SETGID WT_IMPORTANT
#define WT_MMAP WT_IMPORTANT
#define WT_CHDIR WT_IMPORTANT
#define WT_EXIT WT_IMPORTANT

/********************** File name and attribute change ***********************/
#define WT_UNLINK WT_IMPORTANT
#define WT_RMDIR WT_IMPORTANT
#define WT_RENAME WT_IMPORTANT
#define WT_LINK WT_IMPORTANT
#define WT_SYMLINK WT_IMPORTANT
#define WT_CHMOD WT_IMPORTANT
#define WT_FCHMOD WT_IMPORTANT
#define WT_FCHOWN WT_IMPORTANT
#define WT_LCHOWN WT_IMPORTANT
#define WT_CHOWN WT_IMPORTANT
/******************* Data endpoint creation/modification *********************/
#define WT_OPENWR WT_ENDPOINT
#define WT_TRUNC WT_ENDPOINT
#define WT_MKDIR WT_ENDPOINT
#define WT_MKNOD WT_ENDPOINT
#define WT_ACCEPT WT_ENDPOINT
#define WT_CONNECT WT_ENDPOINT
#define WT_SPLICE WT_ENDPOINT
#define WT_VMSPLICE WT_ENDPOINT
#define WT_TEE WT_ENDPOINT
/********************* Unconnected network reads and writes ******************/
#define WT_RECVFROM WT_DGRAM
#define WT_SENDTO WT_DGRAM

/************************* File descriptor tracking **************************/
#define WT_OPENRD WT_FDTRACK
#define WT_DUP WT_FDTRACK
#define WT_PIPE WT_FDTRACK
#define WT_SOCKPAIR WT_FDTRACK
#define WT_SOCKET WT_FDTRACK
/****************** Read, write and other low-priority events ****************/
#define WT_BIND WT_RDWR
#define WT_GETPEER WT_RDWR

#define WT_READ WT_RDWR
#define WT_WRITE WT_RDWR
#define WT_SENDFILE64 WT_RDWR
#define WT_COPY_FILE_RANGE WT_RDWR
/************************ Some exits we *could* ignore  **********************/
#define WT_READEX WT_UNIMPORTANT
#define WT_WRITEX WT_UNIMPORTANT
#define WT_CLOSE WT_UNIMPORTANT
#define WT_MMAPALL WT_UNIMPORTANT

/* On Linux, close is frequent, never fails if FD is valid, so best to ignore */
#define WT_CLOSE_EX WT_REDUNDANT
//-------------------------------------------------------------------------------
// Events subject to logging are defined below. Note that events outside of this
// specification are not even intercepted, so we avoid the base overhead of
// interception (which is non-negligible). Obviously, dynamic control is not
// applicable to events that aren't even intercepted.
//

// Top-level grouping of system calls, you can enable/disable groups at once.

#define LOG_FILENAME_OP // These affect names, incl: mkdir, rename, unlink, etc.
#define LOG_PROC_CONTROL // Ops for one process to modify another: kill,
                         // ptrace,...
#define LOG_PERM_OP      // Permission-related: chmod, chown, setuid, ...
#define LOG_PROC_OP      // Other process ops, e.g., fork, execve, exit, ...
#define LOG_READ         // File and network input operations.
#define LOG_WRITE        // File and network output operations.

#define LOG_ENV // Whether to log environment variables on execve

#define LOG_MMAP // Reads on mmapped files don't need syscalls, so you
                 // to track file-based mmaps to know all read/writes.

#define LOG_OPEN     // -- These create file fds
#define LOG_NET_OPEN // -- These create socket fds
#define LOG_DUP      // -- These change fd associations
#define LOG_PIPE     // -- These create connected fds (incl. sockets)

// More detailed ifdefs that haven't been covered above.

// #define LOG_MMAPALL    // LOG_MMAP logs file-backed and execute permission
// mmaps.
//   To also log mmaps used for mem. alloc, enable this.
#define LOG_CLOSE // These remove fds, enable if useful resource release.

//-------------------------------------------------------------------------------
//
// Miscellaneous definitions for timestamp manipulation
//
#define MS_BIT_SHIFT 24 // Can be 24 or 32. Other values are NOT PERMITTED.

#define getInt24(b0, b1, b2, b3) (((int)b2 << 16) | ((int)b1 << 8) | b0)
#define getInt32(b0, b1, b2, b3) ((getInt24(b1, b2, b3, 0) << 8) | b0)
#define MY_CAT1(x, y) MY_CAT2(x, y)
#define MY_CAT2(x, y) x##y

#define MS_BITS(x) ((x) & ~((1l << MS_BIT_SHIFT) - 1))
#define LS_BITS(x) ((x) & ((1l << MS_BIT_SHIFT) - 1))
#define TS_RECORD(x) (x | MY_CAT1(getInt, MS_BIT_SHIFT)(TSMS_EN, '%', '.', 'x'))
#define CHK_TSREC(p)                                                           \
  (*p == TSMS_EN && *(p + 1) == '%' && *(p + 2) == '.' &&                      \
   (MS_BIT_SHIFT == 24 || *(p + 3) == 'x'))
#define GET_TSREC(p) MS_BITS(*(uint64_t *)(p))

#define FULL_TIME
//-------------------------------------------------------------------------------
//
//  Char. codes for syscalls. Codes for entry (exit) end with _EN (resp., _EX)
//

#define CTRL(x) (x-0x40)

#define ARG_LOOKUP_ERR 'A'
#define ACCEPT_EX    'a'
#define BIND_EX      'b'
#define CLOSE_EN     'C'
#define CHDIR_EX     'c'
#define CHMOD_EX     CTRL('C') // chmod and fchmodat
#define DUP2_EX      'D' // dup, dup2, fcntl-based dup; also dup3
#define DUP_EX       'd'
#define FCHDIR_EX    CTRL('D')
#define EXECVE_EN    'E'
#define EXECVE_EX    'e'
#define EXECVEE_EN   CTRL('E')
#define FORK_EN      'F' // fork and vfork
#define FORK_EX      'f'
#define FCHMOD_EX    CTRL('F')
#define SETGID_EX    'G' // setresgid, setregid, setgid
#define GETPEER_EX   'g'
#define LCHOWN_EX    'H' 
#define INITMOD_EX   'I' // init_module
#define FINITMOD_EX  'i' // finit_module
#define PTRACE_EN    'J'
#define PTRACE_EX    'j'
#define KILL_EN      'K' // kill, tkill, tgkill
#define KILL_EX      'k'
#define TS_KERN      CTRL('K')
#define CLONE_EN     'L' // clone and clone3
#define CLONE_EX     'l'
#define LINK_EX      CTRL('L') // link and linkat
#define MOUNT_EX     'M'
#define MKDIR_EX     'm' // mkdir and mkdirat
#define MMAP_EX      CTRL('M')
#define RENAME_EX    'N' // rename and renameat; also renameat2
#define CONNECT_EX   'n'
#define MKNOD_EX     CTRL('N') // mknod , mknodat
#define CHOWN_EX     'O'
#define OPEN_EX      'o' // open, openat, creat
#define FCHOWN_EX    CTRL('O')
#define PREAD_EX     'P' // Also preadv, preadv2
#define PIPE_EX      'p' // Also pipe2
#define MPROTECT_EX  CTRL('P')
#define RMDIR_EX     'R'
#define READ_EX      'r' // Also readv, recvmsg, recvmmsg
#define ERR_REP      CTRL('R')
#define SYMLINK_EX   'S' // symlink and symlinkat
#define SENDTO_EX    's'
#define SOCKPAIR_EX  CTRL('S')
#define FTRUNC_EX    'T'
#define TRUNC_EX     't'
#define TS_DIFF      CTRL('T')
#define SETUID_EX    'U' // setresuid, setreuid, setuid
#define UNLINK_EX    'u' // unlink and unlinkat
#define UMOUNT_EX    CTRL('U')
#define VMSPLICE_EX  'V'
#define RECVFROM_EX  'v'
#define PWRITE_EX    'W' // Also pwritev and pwritev2
#define WRITE_EX     'w' // Also writev, sendmsg, sendmmsg
#define EXIT_EN      'X' // exit
#define EXITGRP_EN   'x' // exit_group
#define TSMS_EN      'y'
#define SIGNING_KEY_SEED_REC '#'   // Embedded signing-key batch seed
#define SIGNED_RECORD_MAC_REC '@'   // Signed-length and UMAC trailer

#define is_err(ret)                                                            \
  ((-4095 <= ret) && (ret <= -1)) // Interprets syscall ret code.

// Macros related to how id's encode the underlying resource type.

#define FILE_ID                 1
#define PIPE_ID             0b000
#define SELF_NET_ID         0b010
#define LOCAL_NET_ID        0b100
#define FOREIGN_NET_ID      0b110

#define fdtype(id) ((id) & 1? 1 : ((id) & 0x7))
#define isfile(id) (fdtype(id) == FILE_ID)
#define ispipe(id) (fdtype(id) == PIPE_ID)
#define is_self(id) (fdtype(id) == SELF_NET_ID)
#define is_remote(id) (fdtype(id) == FOREIGN_NET_ID)

#define mkid(type, id) \
   (((type)==FILE_ID)? (((id) << 1) | 1) : (((id)<<3)|(type)))
#define getid(id)  (id & 1? (id >> 1) : (id >> 3))

#define INVAL_UID -1
#endif
