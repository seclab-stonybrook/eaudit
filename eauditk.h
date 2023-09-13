#define MAX_SLEN 128 // Max size of string argument fetched from process memory
#define MAX_DLEN 128 // Max size of data arguments fetched from process memory
#define BUFSIZE 2*TX_THRESH + 64*MAX_DLEN // Shd be big enough for execve
/*******************************************************************************
* Maps that can be queried by the user level to determine status and stats     *
********************************************************************************/
enum StatIdx {
   RB_FAIL=0,
   RB_BYTES=1, 
   RB_MSGS=2, 
   RB_WAKEUPS=3, 
   FN_ERR=4,
   DATA_ERR=5,
   ARGV_ERR=6,
   FCNTL_ERR=7,
   SADDR_ERR=8,
   PIPE_ERR=9,
   MMAP_ERR=10,
   FN_TRUNC_ERR=13,
   DATA_TRUNC_ERR=14,
   DATA_READ_OK=15,
   OPEN_DATA_ERR=16,
   SADDR_DATA_ERR=17,
   CONN_DATA_ERR=18,
   SENDTO_DATA_ERR=19,
   BIND_DATA_ERR=20,
   PIPE_READ_DATA_ERR=21,
   SADDR_READ_DATA_ERR=22,
   NUM_SUBJ_CREATED=34,
   MAX_STAT=47
};

// Dynamic congestion control: setting log_wt to w will cause syscalls with 
// weights < w to be dropped. See further down for syscall weights. Congestion
// control is indiscriminate, try "FILTER REPEATED OPERATIONS" first. 

#ifdef __KERNEL__
struct log_lv {  
   u32 log_wt;
};

struct buf {
   u16 idx;
   int weight;
   u64 ts_msbs;
   char d[BUFSIZE];
};

BPF_ARRAY(mystat, u64, MAX_STAT);
BPF_ARRAY(log_level, struct log_lv, 1); // For dynamic control of events to log
BPF_ARRAY(count, u64, 400); // To track # of system call entries
BPF_ARRAY(countexit, u64, 1); // To track # combined system call exits

BPF_PERCPU_ARRAY(buf, struct buf, 1);
BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);
#endif
/******************************************************************************
* Weights of various system calls are specified below. They refer to constant *     * values defined in the Python program that includes/compiles this program.   *
******************************************************************************/
/*************** Privilege escalation and process interference ***************/
#define WT_EXECVE    WT_CRITICAL
#define WT_SETUID    WT_CRITICAL
#define WT_KILL      WT_CRITICAL
#define WT_PTRACE    WT_CRITICAL
#define WT_FIMODULE  WT_CRITICAL
#define WT_IMODULE   WT_CRITICAL

/********************** Process provenance and loading ***********************/
#define WT_FORK      WT_IMPORTANT
#define WT_SETGID    WT_IMPORTANT
#define WT_MMAP      WT_IMPORTANT
#define WT_CHDIR     WT_IMPORTANT
#define WT_EXIT      WT_IMPORTANT

/********************** File name and attribute change ***********************/
#define WT_UNLINK    WT_IMPORTANT
#define WT_RMDIR     WT_IMPORTANT
#define WT_RENAME    WT_IMPORTANT
#define WT_LINK      WT_IMPORTANT
#define WT_SYMLINK   WT_IMPORTANT
#define WT_CHMOD     WT_IMPORTANT

/******************* Data endpoint creation/modification *********************/
#define WT_OPENWR    WT_ENDPOINT
#define WT_TRUNC     WT_ENDPOINT
#define WT_MKDIR     WT_ENDPOINT
#define WT_MKNOD     WT_ENDPOINT
#define WT_ACCEPT    WT_ENDPOINT
#define WT_CONNECT   WT_ENDPOINT
#define WT_SPLICE    WT_ENDPOINT
#define WT_VMSPLICE  WT_ENDPOINT
#define WT_TEE       WT_ENDPOINT

/********************* Unconnected network reads and writes ******************/
#define WT_RECVFROM  WT_DGRAM
#define WT_SENDTO    WT_DGRAM

/************************* File descriptor tracking **************************/
#define WT_OPENRD    WT_FDTRACK
#define WT_DUP       WT_FDTRACK
#define WT_PIPE      WT_FDTRACK
#define WT_SOCKPAIR  WT_FDTRACK
#define WT_SOCKET    WT_FDTRACK
/****************** Read, write and other low-priority events ****************/
#define WT_BIND      WT_RDWR
#define WT_GETPEER   WT_RDWR

#define WT_READ      WT_RDWR
#define WT_WRITE     WT_RDWR


/************************ Some exits we *could* ignore  **********************/
#define WT_READEX    WT_UNIMPORTANT
#define WT_WRITEX    WT_UNIMPORTANT
#define WT_CLOSE     WT_UNIMPORTANT
#define WT_MMAPALL   WT_UNIMPORTANT

/* On Linux, close is frequent, never fails if FD is valid, so best to ignore */
#define WT_CLOSE_EX  WT_REDUNDANT
//-------------------------------------------------------------------------------
// Events subject to logging are defined below. Note that events outside of this
// specification are not even intercepted, so we avoid the base overhead of 
// interception (which is non-negligible). Obviously, dynamic control is not 
// applicable to events that aren't even intercepted.
//

// Top-level grouping of system calls, you can enable/disable groups at once.

#define LOG_FILENAME_OP  // These affect names, incl: mkdir, rename, unlink, etc.
#define LOG_PROC_CONTROL // Ops for one process to modify another: kill, ptrace,...
#define LOG_PERM_OP      // Permission-related: chmod, chown, setuid, ...
#define LOG_PROC_OP      // Other process ops, e.g., fork, execve, exit, ...
#define LOG_READ         // File and network input operations.
#define LOG_WRITE        // File and network output operations.

#define LOG_ENV          // Whether to log environment variables on execve

#define LOG_MMAP         // Reads on mmapped files don't need syscalls, so you
                         // to track file-based mmaps to know all read/writes.

#define LOG_OPEN         // -- These create file fds
#define LOG_NET_OPEN     // -- These create socket fds
#define LOG_DUP          // -- These change fd associations
#define LOG_PIPE         // -- These create connected fds (incl. sockets)

// More detailed ifdefs that haven't been covered above. 

#define LOG_MMAPALL      // LOG_MMAP logs file-backed and execute permission mmaps.
                         // To also log mmaps used for mem. alloc, enable this.
#define LOG_CLOSE        // These remove fds, enable if useful resource release.
#define LOG_PTRACE_EXIT  // If you want to check for failure or return value.
#define LOG_KILL_EXIT    // If you want to check if the syscall failed.

//-------------------------------------------------------------------------------
//
// Miscellaneous definitions for timestamp manipulation
//
#define MS_BIT_SHIFT 24 // Can be 24 or 32. Other values are NOT PERMITTED.

#define getInt24(b0, b1, b2, b3) (((int)b2<<16) | ((int)b1<<8) | b0)
#define getInt32(b0, b1, b2, b3) ((getInt24(b1,b2,b3,0) << 8) | b0)
#define MY_CAT1(x, y) MY_CAT2(x, y)
#define MY_CAT2(x, y) x ## y

#define MS_BITS(x)   ((x) & ~((1l << MS_BIT_SHIFT)-1))
#define LS_BITS(x)   ((x) &  ((1l << MS_BIT_SHIFT)-1))
#define TS_RECORD(x) \
   (x | MY_CAT1(getInt, MS_BIT_SHIFT)(TSMS_EN, '%', '.', 'x'))
#define CHK_TSREC(p) (*p == TSMS_EN && *(p+1) == '%' && *(p+2) == '.' && \
                      (MS_BIT_SHIFT == 24 || *(p+3) == 'x'))
#define GET_TSREC(p) MS_BITS(*(uint64_t *)(p))

//#define FULL_TIME
//-------------------------------------------------------------------------------
//
// Char. codes for syscalls. Codes for entry (exit) end with _EN (resp., _EX)
//

#define CTRL(x) (x-0x40)
#define ACCEPT_EN    'A' // also accept4
#define ACCEPT_EX    'a'
#define BIND_EN      'B'
#define BIND_EX      'b'
#define CLOSE_EN     'C'
#define CLOSE_EX     'c'
#define DUP2_EX      'D' // dup, dup2, fcntl-based dup; also dup3
#define DUP_EX       'd'
#define EXECVE_EN    'E'
#define EXECVE_EX    'e'
#define FORK_EN      'F' // fork and vfork
#define FORK_EX      'f'
#define GETPEER_EN   'G'
#define GETPEER_EX   'g'
#define CHDIR_EN     'H'
#define CHDIR_EX     'h'
#define RMDIR_EN     'I'
#define RMDIR_EX     'i'
#define KILL_EN      'K' // kill, tkill, tgkill
#define KILL_EX      'k'
#define LINK_EN      'L' // link and linkat
#define LINK_EX      'l'
#define MKDIR_EN     'M' // mkdir and mkdirat
#define MKDIR_EX     'm'
#define CONNECT_EN   'N'
#define CONNECT_EX   'n'
#define OPEN_EN      'O' // open, openat, creat
#define OPEN_EX      'o'
#define PIPE_EN      'P' // Also pipe2
#define PIPE_EX      'p'
#define PREAD_EN     'Q' // Also preadv, preadv2
#define PREAD_EX     'q'
#define READ_EN      'R' // Also readv, recvmsg, recvmmsg
#define READ_EX      'r'
#define SETUID_EN    'S' // setresuid, setreuid, setuid
#define SETUID_EX    's'
#define TRUNC_EN     'T'
#define TRUNC_EX     't'
#define UNLINK_EN    'U' // unlink and unlinkat
#define UNLINK_EX    'u'
#define RECVFROM_EN  'V'
#define RECVFROM_EX  'v'
#define WRITE_EN     'W' // Also writev, sendmsg, sendmmsg
#define WRITE_EX     'w'
#define EXIT_EN      'X' // exit
#define EXITGRP_EN   'x' // exit_group
#define SENDTO_EN    'Y'
#define SENDTO_EX    'y'
#define SOCKPAIR_EN  'Z'
#define SOCKPAIR_EX  'z'
#define SYMLINK_EN   '(' // symlink and symlinkat
#define SYMLINK_EX   ')'
#define RENAME_EN    '[' // rename and renameat; also renameat2
#define RENAME_EX    ']'
#define CHMOD_EN     '{' // chmod and fchmodat
#define CHMOD_EX     '}'
#define PWRITE_EN    '`' // Also pwritev and pwritev2
#define PWRITE_EX    '\''
#define PTRACE_EN    '<'
#define PTRACE_EX    '>'
#define CLONE_EN     '^' // clone and clone3
#define CLONE_EX     '$'
#define FCHMOD_EN    '0'
#define FCHMOD_EX    '5'
#define FCHDIR_EN    '1'
#define FCHDIR_EX    '6'
#define FTRUNC_EN    '2'
#define FTRUNC_EX    '7'
#define MMAP_EN      '3'
#define MMAP_EX      '8'
#define MPROTECT_EN  '4'
#define MPROTECT_EX  '9'
#define TS_DIFF      CTRL('D')
#define EXECVEE_EN   CTRL('E')
#define SETGID_EN    CTRL('G') // setresgid, setregid, setgid
#define SETGID_EX    CTRL('H')
#define TS_KERN      CTRL('K')
#define TSMS_EN      CTRL('T')
#define MKNOD_EN     CTRL('M') // mknod , mknodat
#define MKNOD_EX     CTRL('m')
#define I_MODULE_EN  CTRL('I') // init_module
#define I_MODULE_EX  CTRL('j') 
#define FI_MODULE_EN CTRL('F') // finit_module
#define FI_MODULE_EX CTRL('k')
#define SPLICE_EN    CTRL('S') // splice 
#define SPLICE_EX    CTRL('l')
#define VMSPLICE_EN  CTRL('V') // vmsplice
#define VMSPLICE_EX  CTRL('n')
#define TEE_EN       CTRL('J') // tee
#define TEE_EX       CTRL('Y')
#define SOCKET_EN    CTRL('Z') // socket
#define SOCKET_EX    CTRL('z')

#define is_err(ret) ((-4095 <= ret) && (ret <= -1)) // Interprets syscall ret code.
