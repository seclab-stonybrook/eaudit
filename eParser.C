#include <string.h>
#include <numeric>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>
#include <ctype.h>
#include <algorithm>
#include <sys/un.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <signal.h>
/*Changed this for reference*/
#include "Histogram.h"

#include "eauditk.h"
#include "eParser.h"
#include "eConsumer.h"
#include "prthelper.h"
#include "ePrinter.h"
#include "eRecorder.h"

#include "computehash.h"

#include "keygen.h"
using namespace std;

const char* scname[256];
enum ScType {SC_DEFAULT, SC_IMPORTANT, SC_CRITICAL};
ScType cur_sctype;

uint64_t clk_kernel_diff;   // REAL - MONOTONIC clock
uint64_t kernel_ts_msb;     // Just the MS bits from the last Time record
uint64_t kernel_ts;         // The full time stamp for the last record.
uint64_t clk_ts;            // Real time computed from kernel time

uint64_t tamperwin_start;   // as per MONOTONIC clock.

long entry_rec, exit_rec, tsms_rec, tsms_rec1, tsdiff_rec, err_rec;
long exit_errs, trunc_fn, trunc_data;
long sc_count[256], scexit_count[256];
bool exit_op, no_entry;
bool force_ts=true; // forces timestamps for all records. Almost all syscalls
// are NOT split, so no gain here but only complication.
long skipped;
long nr;
int tid, pid, last_tid, last_pid;
int pid_width, a1width, a2width, a3width;
char matching_exit;

long tamper_count, tamper_ccount, tamper_icount;
uint64_t tamper_totclag, tamper_totilag, tamper_totlag;
uint64_t tamper_thisclag, tamper_thisilag, tamper_thislag;
uint64_t tamper_maxclag, tamper_maxilag, tamper_maxlag;
long tamper_windows;
LongHistogram tamperclag, tamperilag, tamperlag, tamper_period;

EConsumer *eConsumer;

// BUFSIZE is the maximum possible record size, per eauditk.h
const int PBUFSIZE = 8*BUFSIZE; 
char *buf = new char[PBUFSIZE];
const char* rbuf = buf;

const char *current_rec;
size_t offset;
uint64_t n_out_of_order, t_out_of_order;
unsigned sn, procid;
bool log_tampered = false;
int n_tampered_events;
bool initial_seed_embedded = false;
int verifier_batch_count = 0;    // tracks how many seed batches have been embedded
unsigned char (*verifier_signing_keys_lo)[SIGNING_KEY_SIZE]; // lower half of verifier signing key ring
unsigned char (*verifier_signing_keys_hi)[SIGNING_KEY_SIZE]; // upper half [SIGNING_KEY_BATCH_SIZE..SIGNING_KEY_RING_SIZE-1]
/**********************************************************************************
 * Some error-printing and helper functions
 *********************************************************************************/

const char* errcode[] = {
/*ecode[0] =*/ "NOERR",
/*ecode[1] =*/ "EPERM",
/*ecode[2] =*/ "ENOENT",
/*ecode[3] =*/ "ESRCH",
/*ecode[4] =*/ "EINTR",
/*ecode[5] =*/ "EIO",
/*ecode[6] =*/ "ENXIO",
/*ecode[7] =*/ "E2BIG",
/*ecode[8] =*/ "ENOEXEC",
/*ecode[9] =*/ "EBADF",
/*ecode[10] =*/ "ECHILD",
/*ecode[11] =*/ "EAGAIN",
/*ecode[12] =*/ "ENOMEM",
/*ecode[13] =*/ "EACCES",
/*ecode[14] =*/ "EFAULT",
/*ecode[15] =*/ "ENOTBLK",
/*ecode[16] =*/ "EBUSY",
/*ecode[17] =*/ "EEXIST",
/*ecode[18] =*/ "EXDEV",
/*ecode[19] =*/ "ENODEV",
/*ecode[20] =*/ "ENOTDIR",
/*ecode[21] =*/ "EISDIR",
/*ecode[22] =*/ "EINVAL",
/*ecode[23] =*/ "ENFILE",
/*ecode[24] =*/ "EMFILE",
/*ecode[25] =*/ "ENOTTY",
/*ecode[26] =*/ "ETXTBSY",
/*ecode[27] =*/ "EFBIG",
/*ecode[28] =*/ "ENOSPC",
/*ecode[29] =*/ "ESPIPE",
/*ecode[30] =*/ "EROFS",
/*ecode[31] =*/ "EMLINK",
/*ecode[32] =*/ "EPIPE",
/*ecode[33] =*/ "EDOM",
/*ecode[34] =*/ "ERANGE",
/*ecode[35] =*/ "EDEADLK",
/*ecode[36] =*/ "ENAMETOOLONG",
/*ecode[37] =*/ "ENOLCK",
/*ecode[38] =*/ "ENOSYS",
/*ecode[39] =*/ "ENOTEMPTY",
/*ecode[40] =*/ "ELOOP",
/*ecode[42] =*/ "ENOMSG",
/*ecode[43] =*/ "EIDRM",
/*ecode[44] =*/ "ECHRNG",
/*ecode[45] =*/ "EL2NSYNC",
/*ecode[46] =*/ "EL3HLT",
/*ecode[47] =*/ "EL3RST",
/*ecode[48] =*/ "ELNRNG",
/*ecode[49] =*/ "EUNATCH",
/*ecode[50] =*/ "ENOCSI",
/*ecode[51] =*/ "EL2HLT",
/*ecode[52] =*/ "EBADE",
/*ecode[53] =*/ "EBADR",
/*ecode[54] =*/ "EXFULL",
/*ecode[55] =*/ "ENOANO",
/*ecode[56] =*/ "EBADRQC",
/*ecode[57] =*/ "EBADSLT",
/*ecode[59] =*/ "EBFONT",
/*ecode[60] =*/ "ENOSTR",
/*ecode[61] =*/ "ENODATA",
/*ecode[62] =*/ "ETIME",
/*ecode[63] =*/ "ENOSR",
/*ecode[64] =*/ "ENONET",
/*ecode[65] =*/ "ENOPKG",
/*ecode[66] =*/ "EREMOTE",
/*ecode[67] =*/ "ENOLINK",
/*ecode[68] =*/ "EADV",
/*ecode[69] =*/ "ESRMNT",
/*ecode[70] =*/ "ECOMM",
/*ecode[71] =*/ "EPROTO",
/*ecode[72] =*/ "EMULTIHOP",
/*ecode[73] =*/ "EDOTDOT",
/*ecode[74] =*/ "EBADMSG",
/*ecode[75] =*/ "EOVERFLOW",
/*ecode[76] =*/ "ENOTUNIQ",
/*ecode[77] =*/ "EBADFD",
/*ecode[78] =*/ "EREMCHG",
/*ecode[79] =*/ "ELIBACC",
/*ecode[80] =*/ "ELIBBAD",
/*ecode[81] =*/ "ELIBSCN",
/*ecode[82] =*/ "ELIBMAX",
/*ecode[83] =*/ "ELIBEXEC",
/*ecode[84] =*/ "EILSEQ",
/*ecode[85] =*/ "ERESTART",
/*ecode[86] =*/ "ESTRPIPE",
/*ecode[87] =*/ "EUSERS",
/*ecode[88] =*/ "ENOTSOCK",
/*ecode[89] =*/ "EDESTADDRREQ",
/*ecode[90] =*/ "EMSGSIZE",
/*ecode[91] =*/ "EPROTOTYPE",
/*ecode[92] =*/ "ENOPROTOOPT",
/*ecode[93] =*/ "EPROTONOSUPPORT",
/*ecode[94] =*/ "ESOCKTNOSUPPORT",
/*ecode[95] =*/ "EOPNOTSUPP",
/*ecode[96] =*/ "EPFNOSUPPORT",
/*ecode[97] =*/ "EAFNOSUPPORT",
/*ecode[98] =*/ "EADDRINUSE",
/*ecode[99] =*/ "EADDRNOTAVAIL",
/*ecode[100] =*/ "ENETDOWN",
/*ecode[101] =*/ "ENETUNREACH",
/*ecode[102] =*/ "ENETRESET",
/*ecode[103] =*/ "ECONNABORTED",
/*ecode[104] =*/ "ECONNRESET",
/*ecode[105] =*/ "ENOBUFS",
/*ecode[106] =*/ "EISCONN",
/*ecode[107] =*/ "ENOTCONN",
/*ecode[108] =*/ "ESHUTDOWN",
/*ecode[109] =*/ "ETOOMANYREFS",
/*ecode[110] =*/ "ETIMEDOUT",
/*ecode[111] =*/ "ECONNREFUSED",
/*ecode[112] =*/ "EHOSTDOWN",
/*ecode[113] =*/ "EHOSTUNREACH",
/*ecode[114] =*/ "EALREADY",
/*ecode[115] =*/ "EINPROGRESS",
/*ecode[116] =*/ "ESTALE",
/*ecode[117] =*/ "EUCLEAN",
/*ecode[118] =*/ "ENOTNAM",
/*ecode[119] =*/ "ENAVAIL",
/*ecode[120] =*/ "EISNAM",
/*ecode[121] =*/ "EREMOTEIO",
/*ecode[122] =*/ "EDQUOT",
/*ecode[123] =*/ "ENOMEDIUM",
/*ecode[124] =*/ "EMEDIUMTYPE",
/*ecode[125] =*/ "ECANCELED",
/*ecode[126] =*/ "ENOKEY",
/*ecode[127] =*/ "EKEYEXPIRED",
/*ecode[128] =*/ "EKEYREVOKED",
/*ecode[129] =*/ "EKEYREJECTED",
/*ecode[130] =*/ "EOWNERDEAD",
/*ecode[131] =*/ "ENOTRECOVERABLE"
};

static void
errexit(const char* msg, const char* buf=0, size_t len=0) {
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

FILE *pofp, *cofp;
bool use_seqnum = true;
extern bool use_procid, prt_musec_ts, prtInParser, verifyLog;

static void
errmsg(const char* msg, const char *p, const char *q) {
   fflush(pofp);
   fprintf(stderr, "***** %s: at or near offset %ld:\n",
      msg, offset+(current_rec-rbuf));
   fwrite(current_rec, p-current_rec, 1, stderr);
   fprintf(stderr, "\n**** Text following error is: ");
   fwrite(p, min(32l, q-p), 1, stderr);
   fprintf(stderr, "\n *******************************************\n");
}

static void
prt_ts_and_pid() {
   // @@@@ About 70% of the runtime for printing is from just the next line!
   //fprintf(pofp, "%ld: pid=%d: ", ts, pid);
   prttspid(clk_ts, pid, sn, procid, use_seqnum, use_procid, prt_musec_ts, pofp);
   if (tid != pid)
      fprintf(pofp, "tid=%u: ", tid);
}

static void
init_scname() {
   scname[ACCEPT_EX] = "accept";
   scname[BIND_EX] = "bind";
   scname[CHDIR_EX] = "chdir";
   scname[CHMOD_EX] = "chmod";
   scname[CLONE_EN] = scname[CLONE_EX] = "clone";
   scname[CLOSE_EN] = "close";
   scname[CONNECT_EX] = "connect";
   scname[DUP_EX] = "dup";
   scname[DUP2_EX] = "dup2";
   scname[EXECVE_EN] = scname[EXECVE_EX] = scname[EXECVEE_EN] = "execve";
   scname[EXIT_EN] = "exit";
   scname[EXITGRP_EN] = "exitgrp";
   scname[ERR_REP] = "argerr"; // Lookup of saved arg frm sc entry failed at exit
   scname[FCHDIR_EX] = "fchdir";
   scname[FCHMOD_EX] = "fchmod";
   scname[FORK_EN] = scname[FORK_EX] = "fork";
   scname[FTRUNC_EX] = "ftruncate";
   scname[GETPEER_EX] = "getpeername";
   scname[KILL_EN] = scname[KILL_EX] = "kill";
   scname[LINK_EX] = "link";
   scname[MKDIR_EX] = "mkdir";
   scname[MMAP_EX] = "mmap";
   scname[MPROTECT_EX] = "mprotect";
   scname[OPEN_EX] = "open";
   scname[PREAD_EX] = "pread";
   scname[PTRACE_EN] = scname[PTRACE_EX] = "ptrace";
   scname[PWRITE_EX] = "pwrite";
   scname[READ_EX] = "read";
   scname[RECVFROM_EX] = "recvfrom";
   scname[RENAME_EX] = "rename";
   scname[RMDIR_EX] = "rmdir";
   scname[SENDTO_EX] = "sendto";
   scname[SETGID_EX] = "setgid";
   scname[SETUID_EX] = "setuid";
   scname[SYMLINK_EX] = "symlink";
   scname[TRUNC_EX] = "truncate";
   scname[UNLINK_EX] = "unlink";
   scname[WRITE_EX] = "write";
   scname[MKNOD_EX] = "mknod";
   scname[FINITMOD_EX] = "finit_module" ;
   scname[INITMOD_EX] = "init_module";
   scname[VMSPLICE_EX] = "vmsplice";
   scname[CHOWN_EX] = "chown";
   scname[FCHOWN_EX] = "fchown";
   scname[LCHOWN_EX] = "lchown";
   scname[MOUNT_EX] = "mount";
   scname[UMOUNT_EX] = "umount";
}

/**********************************************************************************
 * Helper functions to parse record fields
 *********************************************************************************/

static bool
get_long(const char*& p, const char* q, int width, long& v) {
   int8_t i8;
   int16_t i16;
   int32_t i32;

   if (p + width >= q) return false;
   switch (width) {
   case 1: i8 =  *(const int8_t  *)p; v =  i8; break;
   case 2: i16 = *(const int16_t *)p; v = i16; break;
   case 4: i32 = *(const int32_t *)p; v = i32; break;
   case 8: v   = *(const long    *)p; break;
   default: return false;
   }

   p += width;
   return true;
}

/******************************************************************************
* Helper functions for parsing. Typically matched with the corresponding      *
* formatting function in the ebpf probe code.                                 *
******************************************************************************/
static bool
get_ts_and_widths(const char*& p, const char* q) {
   // Read and process timestamp
   if (p+5 >= q) return false;

   uint64_t last_kernel_ts = kernel_ts;
#ifdef FULL_TIME
   kernel_ts = *(const uint64_t*)p; p+= 8;
   //uint64_t ts_lsb = LS_BITS(kernel_ts);
   //if (kernel_ts != kernel_ts_msb + ts_lsb)
     // fprintf(stderr, "diff: %ld\n", (long)(kernel_ts - kernel_ts_msb - ts_lsb));
#else
   uint32_t ts_lsb = *(const int*)p; p+= 3;
   ts_lsb = LS_BITS(ts_lsb);
   kernel_ts = kernel_ts_msb + ts_lsb;
#endif
   if (kernel_ts + 1000 < tamperwin_start) {
      if (cur_sctype == SC_CRITICAL) {
         tamper_ccount++;
         tamper_thisclag = max(tamper_thisclag, tamperwin_start - kernel_ts);
         tamper_maxclag = max(tamper_maxclag, tamperwin_start - kernel_ts);
      }
      else if (cur_sctype == SC_IMPORTANT) {
         tamper_icount++;
         tamper_thisilag = max(tamper_thisilag, tamperwin_start - kernel_ts);
         tamper_maxilag = max(tamper_maxilag, tamperwin_start - kernel_ts);
      }
      tamper_count++;
      tamper_thislag = max(tamper_thislag, tamperwin_start - kernel_ts);
      tamper_maxlag = max(tamper_maxlag, tamperwin_start - kernel_ts);
   }
   clk_ts = kernel_ts + clk_kernel_diff;
   if (kernel_ts < last_kernel_ts) {
      uint64_t backdrift = (last_kernel_ts - kernel_ts);
      if (backdrift > 1e10 /*&& entry_rec+exit_rec > 500*/)
         fprintf(stderr, "Backdrift by %g seconds after %ld records\n", 
                 backdrift/1e9, entry_rec+exit_rec);
      if (backdrift < 1e11) {
         n_out_of_order++;
         t_out_of_order += backdrift;
      }
   }

   uint8_t b = *p; p++;
   pid_width = 1 << (b>>6);
   a1width = 1 << ((b>>4)&3);
   a2width = 1 << ((b>>2)&3);
   a3width = 1 << (b&3);

   long pid_tgid;
   if (!get_long(p, q, pid_width, pid_tgid))
      return false;

   last_pid = pid;
   last_tid = tid;
   if (pid_width <= 4)
      pid = tid = (int)pid_tgid;
   else {
      pid = pid_tgid >> 32;
      tid = pid_tgid & ((1ul << 32)-1);
   }

   if (prtInParser) {
      if (!exit_op || no_entry || force_ts || pid!=last_pid || tid!=last_tid)
         prt_ts_and_pid();
   }
   return true;
}

static bool
get_long_ex(long& a1, const char*& p, const char* q) {
   if (p + 8 >= q) {
      return false;
   }
   a1 = *(const uint64_t*)p;
   p += 8;
   return true;
}

static bool
get_long1(long& a1, const char*& p, const char* q) {
   if (!get_ts_and_widths(p, q)) return false;
   if (!get_long(p, q, a1width, a1)) return false;
   return true;
}

static bool
get_long2(long& a1, long& a2, const char*& p, const char* q) {
   if (!get_long1(a1, p, q)) return false;
   if (!get_long(p, q, a2width, a2)) return false;
   return true;
}

static bool
get_long3(long& a1, long& a2, long& a3, const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_long(p, q, a3width, a3)) return false;
   return true;
}

static bool
get_long4(long& a1, long& a2, long& a3, long& a4, const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_long(p, q, a3width, a3)) return false;
   if (!get_long_ex(a4, p, q)) return false;
   return true;
}

static bool
get_long5(long& a1, long& a2, long& a3, long& a4, long& a5, 
      const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_long(p, q, a3width, a3)) return false;
   if (!get_long_ex(a4, p, q)) return false;
   if (!get_long_ex(a5, p, q)) return false;
   return true;
}

static char strbuf[PBUFSIZE];
static char *strbuf_next;

static inline void
reset_strbuf() {
   strbuf_next = strbuf;
}

static inline int
rem_spc_strbuf() {
   return &strbuf[PBUFSIZE] - strbuf_next - 8; // 8 for additional error margin
}

static inline char*
get_strbuf() {
   return strbuf_next;
}

static inline char*
copy2strbuf(const char* src, int len) {
   char *rv = strbuf_next;
   assert_abort(rem_spc_strbuf() > len);
   memcpy(strbuf_next, src, len);
   strbuf_next += len;
   return rv;
}

static inline char*
copy2strbuf(const char* src, int len, char term) {
   char *rv = strbuf_next;
   assert_abort(rem_spc_strbuf() > len);
   memcpy(strbuf_next, src, len);
   strbuf_next += len-1;
   if (*strbuf_next != term) {
      if (*strbuf_next == '\0')
         *strbuf_next = term;
      else {
         strbuf_next++;
         *strbuf_next = term;
      }
   }
   strbuf_next++;
   return rv;
}

static void
repl_last_char_strbuf(char c) {
   assert_abort(strbuf_next > strbuf);
   *(strbuf_next - 1) = c;
}

static bool
get_string(char*& s, const char*& p, const char* q, char term='\0') {
   int len = (uint8_t)*p; p++;
   if (len >= MAX_DLEN) trunc_fn++;
   if (p+len >= q) return false;
   s = copy2strbuf(p, len, term);
   p += len;
   return true;
}

static bool
get_str_long1(char*& s, long& a1, const char*& p, const char* q) {
   if (!get_long1(a1, p, q)) return false;
   if (!get_string(s, p, q)) return false;
   return true;
}

static bool
get_str_long2(char*& s, long& a1, long& a2,
               const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_string(s, p, q)) return false;
   return true;
}

static bool
get_str_long3(char*& s, long& a1, long& a2, long& a3,
               const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_string(s, p, q)) return false;
   return true;
}

static bool
get_str_long4(char*& s, long& a1, long& a2, long& a3, long& a4,
               const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_long_ex(a4, p, q)) return false;
   if (!get_string(s, p, q)) return false;
   return true;
}

static bool
get_str_long5(char*& s, long& a1, long& a2, long& a3, long& a4, long& a5,
               const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_long_ex(a4, p, q)) return false;
   if (!get_long_ex(a5, p, q)) return false;
   if (!get_string(s, p, q)) return false;
   return true;
}

static bool
get_str2_long3(char*& s1, char*& s2, long& a1, long& a2, long &a3,
               const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_string(s1, p, q)) return false;
   if (!get_string(s2, p, q)) return false;
   return true;
}

static bool
get_str2_long5(char*& s1, char*& s2, long& a1, long& a2, long &a3, long &a4,
               long& a5, const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_long_ex(a4, p, q)) return false;
   if (!get_long_ex(a5, p, q)) return false;
   if (!get_string(s1, p, q)) return false;
   if (!get_string(s2, p, q)) return false;
   return true;
}

static bool
get_str3_long2(char *&s1, char *&s2, char *&s3, long &a1, long &a2,
                           const char *&p, const char *q) {
  if (!get_long2(a1, a2, p, q))
    return false;
  if (!get_string(s1, p, q))
    return false;
  if (!get_string(s2, p, q))
    return false;
  if (!get_string(s3, p, q))
    return false;
  return true;
}

static bool
get_data(uint8_t*& d, unsigned& dlen, const char*& p, const char* q) {
   dlen = (uint8_t)*p; p++;
   if (dlen > MAX_DLEN) trunc_data++;
   if (p+dlen >= q) return false;
   d = (uint8_t*)copy2strbuf(p, dlen);
   p += dlen;
   return true;
}

static bool
get_data_long2(uint8_t*& d, unsigned& dlen, long& a1, long &a2,
               const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_data(d, dlen, p, q)) return false;
   return true;
}

static bool
get_data_long3(uint8_t*& d, unsigned& dlen, long& a1, long &a2, long &a3,
               const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (!get_data(d, dlen, p, q)) return false;
   return true;
}

static bool 
get_binary(char*& d, unsigned& dlen, const char*& p, const char* q) {
   if (p >= q) return false; 

   dlen = (uint8_t)*p;  // Read the stored length
   p++;  // Move past length field

   if (dlen > MAX_DLEN) {
      trunc_data++;  // Handle potential data truncation
      return false;
   }

   if (p + dlen > q) return false; 

   d = (char*)p; 
   p += dlen;  

   return true; 
}


static void 
regenerate_signing_key_batch(unsigned char (*signing_key_batch_out)[SIGNING_KEY_SIZE], char *embedded_seed) {

   unsigned char batch_seed[SIGNING_KEY_SIZE];
   memcpy(batch_seed, embedded_seed, SIGNING_KEY_SIZE);
#ifdef TAMPER_DETECT
   generate_signing_keys(batch_seed, (unsigned char *)signing_key_batch_out);
#endif
   explicit_bzero(batch_seed, sizeof(batch_seed));
}

static inline bool
consume_signing_key_seed(const char*& p, const char* q, char*& embedded_seed) {
   unsigned slen = 0;
   return get_binary(embedded_seed, slen, p, q);
}

static inline bool
consume_signed_record_mac(const char*& p, const char* q, char*& mac_tag,
                          unsigned& signed_payload_bytes) {
   unsigned slen = 0;
   char *mac_record = NULL;
   if (!get_binary(mac_record, slen, p, q)) return false;
   if (slen != SIGNED_RECORD_TRAILER_SIZE) return false;
   signed_payload_bytes = ((uint8_t)mac_record[0]) |
                          (((uint8_t)mac_record[1]) << 8);
   mac_tag = mac_record + SIGNED_RECORD_LEN_SIZE;
   return true;
}

static bool
read_embedded_seed_and_mac(const char*& p, const char* q, char*& embedded_seed,
                           char*& mac_tag, unsigned& signed_payload_bytes) {
   embedded_seed = NULL;
   mac_tag = NULL;
   signed_payload_bytes = 0;
   if (verifyLog) {
      if (*p == SIGNING_KEY_SEED_REC) {
         p++;
         if (!consume_signing_key_seed(p, q, embedded_seed)) return false;

         if (!initial_seed_embedded) {
            // First seed: generate batch 0 into lower half of the verifier ring.
            initial_seed_embedded = true;
            regenerate_signing_key_batch(verifier_signing_keys_lo, embedded_seed);
            verifier_batch_count = 1;
         } else {
            // Subsequent seeds regenerate the next batch into alternating halves.
            if (verifier_batch_count % 2 == 1) {
               regenerate_signing_key_batch(verifier_signing_keys_hi, embedded_seed);
            } else {
               regenerate_signing_key_batch(verifier_signing_keys_lo, embedded_seed);
            }
            verifier_batch_count++;
         }
      }

      if (*p == SIGNED_RECORD_MAC_REC) {
         p++;
         if (!consume_signed_record_mac(p, q, mac_tag, signed_payload_bytes))
            return false;
      }
   }
   else {
      if (*p == SIGNING_KEY_SEED_REC) {
         p++;
         if (!consume_signing_key_seed(p, q, embedded_seed)) return false;
      }
      if (*p == SIGNED_RECORD_MAC_REC) {
         p++;
         unsigned slen = 0;
         if (!get_binary(mac_tag, slen, p, q)) return false;
      }
   }
   return true;
}

unsigned char*
get_signing_key_for_sn(uint32_t sn) {
   // sn is already mod SIGNING_KEY_RING_SIZE (18-bit in record).
   if (sn < SIGNING_KEY_BATCH_SIZE) {
      return verifier_signing_keys_lo[sn];
   } else {
      return verifier_signing_keys_hi[sn - SIGNING_KEY_BATCH_SIZE];
   }
}

static bool
verify_record_mac(unsigned signed_payload_bytes, const char *signed_payload_end,
                  const char *mac_tag) {
   if (signed_payload_bytes == 0 ||
       current_rec + signed_payload_bytes > signed_payload_end)
      return false;

   uint64_t computed_mac = 0;
#ifdef TAMPER_DETECT
   unsigned char *key = get_signing_key_for_sn(sn);
   computed_mac = compute_umac3_mac((uint8_t*)current_rec, signed_payload_bytes,
                                    (uint8_t*)key);
#endif

   uint64_t recorded_mac = 0;
   memcpy(&recorded_mac, mac_tag, SIGNED_RECORD_MAC_SIZE);

   if (computed_mac != recorded_mac)
      return false;
   return true;
}

static constexpr size_t VERIFIER_SIGNING_KEY_BATCH_BYTES =
   SIGNING_KEY_BATCH_SIZE * SIGNING_KEY_SIZE;

struct RecordCryptoFields {
   char *embedded_seed = NULL;
   char *mac_tag = NULL;
   unsigned signed_payload_bytes = 0;
   const char *signed_payload_end = NULL;
};

static bool
read_record_crypto_fields(const char*& p, const char* q, RecordCryptoFields& crypto) {
   crypto = RecordCryptoFields();
   crypto.signed_payload_end = p;
   return read_embedded_seed_and_mac(p, q, crypto.embedded_seed, crypto.mac_tag,
                                     crypto.signed_payload_bytes);
}

static void
mark_record_tampered(bool& is_tampered) {
   log_tampered = true;
   n_tampered_events += 1;
   is_tampered = true;
}

static void
verify_record_crypto_fields(const char*& p, const char* q,
                            const RecordCryptoFields& crypto,
                            bool& is_tampered) {
   (void)p;
   (void)q;
   if (!verifyLog || crypto.mac_tag == NULL)
      return;

   if (!initial_seed_embedded)
      return;

   if (sn >= SIGNING_KEY_RING_SIZE)
      return;

   if (!verify_record_mac(crypto.signed_payload_bytes,
                          crypto.signed_payload_end, crypto.mac_tag)) {
      mark_record_tampered(is_tampered);
   }
}

static bool
allocate_verifier_signing_keys() {
   verifier_signing_keys_lo = (unsigned char(*)[SIGNING_KEY_SIZE])
      calloc(SIGNING_KEY_BATCH_SIZE, SIGNING_KEY_SIZE);
   verifier_signing_keys_hi = (unsigned char(*)[SIGNING_KEY_SIZE])
      calloc(SIGNING_KEY_BATCH_SIZE, SIGNING_KEY_SIZE);
   return verifier_signing_keys_lo != NULL && verifier_signing_keys_hi != NULL;
}

static void
clear_and_free_verifier_signing_keys(unsigned char (*&keys)[SIGNING_KEY_SIZE]) {
   if (keys != NULL) {
      explicit_bzero(keys, VERIFIER_SIGNING_KEY_BATCH_BYTES);
      free(keys);
      keys = NULL;
   }
}

// %%%% Most overhead in eParse comes from printing --- 80% or more. It used to
// %%%% be more like 95%, then a few heavy hitters --- just a few lines of code
// %%%% altogether --- were hand-tweaked to improve performance by more than 2x.
// %%%% There is still scope for improvement, but the easy stuff is done.

/**********************************************************************************
 * Functions to parse syscalls and arguments
 *********************************************************************************/
static bool
exit_open(const char*& p, const char* q) {
   char* fn;
   long md_fl;
   long at, fl, md;
   long at_id, ret_id;
   long ret;

   if (!get_str_long5(fn, md_fl, at, ret, at_id, ret_id, p, q))
      return false;

   md = md_fl >> 32;
   fl = md_fl & 0xffffffff;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->openat(OPEN_EX, sn, clk_ts, tid, pid, at, fn, fl, md, ret,
                        at_id, ret_id);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_open(at, fn, fl, md, ret, at_id, ret_id, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_sc(uint8_t sc, const char*& p, const char* q) {
   long ret;
   no_entry = false;
   if (!get_long1(ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->sc_exit(sc, sn, clk_ts, tid, pid, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_ret(scname[sc], ret, pid, tid, last_pid, last_tid, force_ts, pofp, 
                     is_tampered);

   if (*p != '\n')
    errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
enter_close(const char*& p, const char* q) {
   long fd, unrep_rd, unrep_wr;

   exit_op = false;
   if (!get_long3(fd, unrep_rd, unrep_wr, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   // Close return value is not important. Let us not wait for it (report 0)
   if (eConsumer)
      eConsumer->close(CLOSE_EN, sn, clk_ts, tid, pid, fd, unrep_rd, unrep_wr, 0);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser) {
      prt_close(fd, unrep_rd, unrep_wr, pofp, is_tampered);
   }
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_dup(char sc, const char*& p, const char* q) {
   long fd, ret;

   if (!get_long2(fd, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->dup(sc, sn, clk_ts, tid, pid, fd, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_dup(scname[(unsigned)sc], fd, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_pipe(uint8_t sc, const char*& p, const char* q) {
   long ret;
   if (!get_long1(ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;

   long fd1 = (int)ret;
   long fd2 = (int)(ret>>32);
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->pipe(sc, sn, clk_ts, tid, pid, sc==SOCKPAIR_EX, fd1, fd2);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_pipe_spair(sc, fd1, fd2, pofp, is_tampered);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
exit_read(const char*& p, const char* q) {
   long fd, id, ret;

   if (!get_long3(fd, id, ret, p, q))
         return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->read(READ_EX, sn, clk_ts, tid, pid, fd, id, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_read(fd, id, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exitt_saddr(uint8_t sc, const char*& p, const char* q) {
   long ret, fd, id=0;
   uint8_t *saddr;
   unsigned slen=0;

   if (!get_data_long3(saddr, slen, fd, ret, id, p, q))
      return false;
   if (is_err(ret)) exit_errs++;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
     eConsumer->accRcvfPeer(sc, sn, clk_ts, tid, pid, fd, id, saddr, slen, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);
   
   if (prtInParser)
      prt_saddr(scname[sc], fd, id, ret, saddr, slen, pofp);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
exit_connect(const char*& p, const char* q) {
   long fd, id, ret;
   uint8_t* saddr;
   unsigned slen=0;

   if (!get_data_long3(saddr, slen, fd, id, ret, p, q)) {
      fprintf(stderr, "connect_ex error, dlen=%d, char=%c\n",
         slen, (char)slen);
      return false;
   }
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->connect(CONNECT_EX, sn, clk_ts, tid, pid, fd, id, saddr,
         slen, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_connect(fd, id, ret, saddr, slen, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_bind(const char*& p, const char* q) {
   long fd;
   uint8_t* saddr;
   long ret;
   unsigned slen=0;

   if (!get_data_long2(saddr, slen, fd, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
       eConsumer->bind(BIND_EX, sn, clk_ts, tid, pid, fd, saddr,
         slen, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_bind(fd, saddr, slen, ret, pofp, is_tampered);
   
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_sendto(const char*& p, const char* q) {
   long fd, ret;
   uint8_t* saddr;
   unsigned slen=0;

   if (!get_data_long2(saddr, slen, fd, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->sendto(SENDTO_EX, sn, clk_ts, tid, pid, fd,
         saddr, slen, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_sendto(fd, saddr, slen, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_write(const char*& p, const char* q) {
   long fd, id, ret;

   if (!get_long3(fd, id, ret, p, q))
         return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->write(WRITE_EX, sn, clk_ts, tid, pid, fd, id, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_write(fd, id, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_truncate(const char*& p, const char* q) {
   char* fn;
   long len;
   long ret;
   if (!get_str_long2(fn, len, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
       eConsumer->truncate(TRUNC_EX, sn, clk_ts, tid, pid, fn, len, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_truncate(fn, len, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_ftruncate(const char*& p, const char* q) {
   long len, id, fd, ret;

   if (!get_long3(id, len, ret, p, q))
      return false;

   fd = ret >> 1;
   ret = (ret & 0x1)? -1 : 0;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;
   
   if (eConsumer)
      eConsumer->ftruncate(FTRUNC_EX, sn, clk_ts, tid, pid, fd, id, len, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_ftruncate(fd, id, len, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_mmap(const char*& p, const char* q) {
   long id, addr, len, flags, ret;
   int prot;
   // Uncomment the next line *if* LOG_MMAPALL is *NOT* enabled in the log
   cur_sctype = SC_IMPORTANT;
   if (!get_long5(id, addr, len, flags, ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   prot = flags & 0x7;
   flags = (((uint64_t)flags) >> 32);

   if (eConsumer)
      eConsumer->mmapex(MMAP_EX, sn, clk_ts, tid, pid, id, 
                      addr, len, prot, flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_mmap(addr, len, prot, flags, id, ret, pofp, is_tampered);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
error_entry(const char*& p, const char* q) {
   long errcode, sc;
   last_tid = 0; // Force a new record, if printing.
   if (!get_long2(errcode, sc, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_error_entry(errcode, sc, pofp);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   tid = 0; // Force the next record to be new, if printing
   return true;
}

static bool
exit_mprotect(const char*& p, const char* q) {
   long addr, len, prot, ret;

   // Uncomment the next line *if* LOG_MMAPALL is *NOT* enabled in the log
   cur_sctype = SC_IMPORTANT;

   if (!get_long3(addr, len, ret, p, q))
      return false;

   prot = ((int)(ret & 0xffffffff));
   ret = ret >> 32;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->mprotect(MPROTECT_EX, sn, clk_ts, tid, pid, addr, len, prot, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_mprotect(addr, len, prot, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_unlink(const char*& p, const char* q) {
   char* fn;
   long fd, id;
   long ret;
   cur_sctype = SC_IMPORTANT;

   if (!get_str_long3(fn, fd, id, ret, p, q))
      return false;

   fd = (int)fd;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;
   if (eConsumer)
      eConsumer->unlinkat(UNLINK_EX, sn, clk_ts, tid, pid, fd, id, fn, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_unlink(fd, id, fn, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_mkdir(const char*& p, const char* q) {
   char* fn;
   long fd, id, mode, ret;

   if (!get_str_long3(fn, fd, id, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   mode = ret >> 32;
   ret = (int)ret;
   if (eConsumer)
      eConsumer->mkdirat(MKDIR_EX, sn, clk_ts, tid, pid, fd, id, fn, mode, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_mkdir(fd, id, fn, mode, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_mknod(const char*& p, const char* q) {
   char* fn;
   long fd, id, mode, dev, ret;

   if (!get_str_long4(fn, fd, dev, ret, id, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   mode = ret >> 8;
   ret = (char)ret;

   if (eConsumer)
      eConsumer->mknodat(MKNOD_EX, sn, clk_ts, tid, pid, fd, id,fn,mode,dev,ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_mknod(fd, id, fn, mode, dev, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_rmdir(const char*& p, const char* q) {
   char* fn;
   long ret;
   if (!get_str_long1(fn, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->rmdir(RMDIR_EX, sn, clk_ts, tid, pid, fn, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_rmdir(fn, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_chdir(const char*& p, const char* q) {
   char* fn;
   long ret;
   cur_sctype = SC_IMPORTANT;
   if (!get_str_long1(fn, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_chdir(fn, ret, pofp, is_tampered);

   if (eConsumer)
      eConsumer->chdir(CHDIR_EX, sn, clk_ts, tid, pid, fn, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_fchdir(const char*& p, const char* q) {
   long fd, id;
   long ret;
   cur_sctype = SC_IMPORTANT;
   if (!get_long3(fd, id, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->fchdir(FCHDIR_EX, sn, clk_ts, tid, pid, fd, id, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_fchdir(fd, id, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_link(const char*& p, const char* q) {
   char *s1, *s2;
   long ofd, nfd, oid, nid, flags, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long5(s1, s2, ofd, nfd, ret, oid, nid, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   flags = ret >> 32;
   ret = (int)ret;

   if (eConsumer)
      eConsumer->linkat(LINK_EX, sn, clk_ts, tid, pid, ofd, oid, s1, nfd, nid,
                             s2, flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_link(ofd, oid, nfd, nid, s1, s2, flags, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool exit_chown(const char *&p, const char *q) {
  char *s1;
  long user, group, ret, fd, id, flags;

  cur_sctype = SC_IMPORTANT;
  if (!get_str_long5(s1, fd, user, group, id, ret, p, q))
    return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

  flags = ret >> 8;
  ret = (char)ret;

   if (eConsumer)
      eConsumer->chownat(CHOWN_EX, sn, clk_ts, tid, pid, fd, id, s1, 
                         user, group, flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

  if (prtInParser)
    prt_chown(s1, user, group, fd, id, flags, ret, pofp, is_tampered);
  if (*p != '\n')
    errmsg("Missing newline", p, q);
  p++; // Skip the trailing newline character at the end of the record
  return true;
}

static bool exit_fchown(const char *&p, const char *q) {
  long fd, id, user, group, ret;

  cur_sctype = SC_IMPORTANT;
  if (!get_long4(user, group, ret, id, p, q))
    return false;

  fd = ret >> 8;
  ret = (char)ret;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->fchown(FCHOWN_EX, sn, clk_ts, tid, pid, fd, id, user, group, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);
  if (prtInParser)
      prt_fchown(fd, id, user, group, ret, pofp, is_tampered);

  if (*p != '\n')
    errmsg("Missing newline", p, q);
  p++; // Skip the trailing newline character at the end of the record
  return true;
}

static bool exit_mount(const char *&p, const char *q) {
  char *src, *dst, *fstp;
  long flags, ret;

  cur_sctype = SC_IMPORTANT;
  if (!get_str3_long2(src, dst, fstp, flags, ret, p, q))
    return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
     eConsumer->mount(MOUNT_EX, sn, clk_ts, tid, pid, src, dst, fstp, flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

  if (prtInParser)
      prt_mount(src, dst, fstp, flags, ret, pofp, is_tampered);

  if (*p != '\n')
    errmsg("Missing newline", p, q);
  p++; // Skip the trailing newline character at the end of the record
  return true;
}

static bool exit_umount(const char *&p, const char *q) {
  char *s1;
  long flags, ret;

  cur_sctype = SC_IMPORTANT;
  if (!get_str_long2(s1, flags, ret, p, q)) {
      return false;
  }
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
     eConsumer->umount(UMOUNT_EX, sn, clk_ts, tid, pid, s1, flags,
         ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

  if (prtInParser)
      prt_umount(s1, flags, ret, pofp, is_tampered);


  if (*p != '\n')
    errmsg("Missing newline", p, q);
  p++; // Skip the trailing newline character at the end of the record
  return true;
}

static bool
exit_symlink(const char*& p, const char* q) {
   char *s1, *s2;
   long fd, id, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long3(s1, s2, fd, id, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->symlinkat(SYMLINK_EX, sn, clk_ts, tid, pid, s1,
         fd, id, s2, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_symlink(fd, id, s1, s2, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_rename(const char*& p, const char* q) {
   char *s1, *s2;
   long ofd, nfd, oid, nid, flags;
   long ret;
   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long5(s1, s2, ofd, nfd, ret, oid, nid, 
          p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   flags = ret >> 32;
   ret = (int)ret;
   
   if (eConsumer)
      eConsumer->renameat(RENAME_EX, sn, clk_ts, tid, pid, ofd, oid, s1,
                              nfd, nid, s2, flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_rename(ofd, oid, nfd, nid, s1, s2, flags, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_vmsplice(const char*& p, const char* q) {
   long fd, id, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3(fd, id, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->vmsplice(VMSPLICE_EX, sn, clk_ts, tid, pid, (int)fd,
                            id, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_vmsplice(fd, id, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

/*
static bool
enter_socket(const char*& p, const char* q) {
   long fmly, type, proto, ret=0;

   cur_sctype = SC_IMPORTANT;
   exit_op = false;
   if (!get_long3(fmly, type, proto, p, q))
      return false;
   if (eConsumer)
      eConsumer->socket(SOCKET_EX, sn, clk_ts, tid, pid, fmly,
         type, proto, ret);

   if (prtInParser)
      prt_socket(fmly, type, proto, pofp);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}
*/

static bool
enter_kill(const char*& p, const char* q) {
   long pid_tgid, sig;

   cur_sctype = SC_CRITICAL;
   exit_op = false;
   if (!get_long2(pid_tgid, sig, p, q))
      return false;
   int pid1 = pid_tgid & ((1ul << 32)-1);
   int tid1 = pid_tgid >> 32;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_kill(KILL_EX, sn, clk_ts, tid, pid, pid1, tid1, sig);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_kill_no_ret(pid1, tid1, (int)sig, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_ptrace(const char*& p, const char* q) {
   long target_tid, req;

   cur_sctype = SC_CRITICAL;
   exit_op = false;
   if (!get_long2(req, target_tid, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_ptrace(PTRACE_EX, sn, clk_ts, tid, pid,
         req, (int)target_tid);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_ptrace((int)target_tid, req, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_chmod(const char*& p, const char* q) {
   char* fn;
   long fd, id, mode, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_str_long4(fn, fd, mode, ret, id, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->chmodat(CHMOD_EX, sn, clk_ts, tid, pid, fd, id,
         fn, mode, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_chmod(fd, id, fn, mode, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_fchmod(const char*& p, const char* q) {
   long fd, id, mode, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3(mode, id, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   fd = ret >> 8;
   ret = (char)ret;

   if (eConsumer)
      eConsumer->fchmod(FCHMOD_EX, sn, clk_ts, tid, pid, fd, id, mode, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_fchmod(fd, id, mode, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_setuid(const char*& p, const char* q) {
   long ruid, euid, suid, ret;

   cur_sctype = SC_CRITICAL;
   if (!get_long4(ruid, euid, suid, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->setuid(SETUID_EX, sn, clk_ts, tid, pid,(int)ruid,
                            (int)euid,(int)suid, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_setuid((int)euid, (int)ruid, (int)suid, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_setgid(const char*& p, const char* q) {
   long rgid, egid, sgid, ret;

   cur_sctype = SC_IMPORTANT;
   if (!get_long4(rgid, egid, sgid, ret, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->setgid(SETGID_EX, sn, clk_ts, tid, pid,
                            (int)rgid, (int)egid,
                              (int)sgid, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_setgid((int)egid, (int)rgid, (int)sgid, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_fork(const char*& p, const char* q) {
   cur_sctype = SC_IMPORTANT;
   exit_op = false;
   if (!get_ts_and_widths(p, q)) return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_fork(pofp, is_tampered);

   if (eConsumer)
      eConsumer->ent_clone(FORK_EX, sn, clk_ts, tid, pid, 0);
   
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exitt_ids(uint8_t sc, const char*& p, const char* q) {
   long ret;
   long uid_gid, cgroup;

   no_entry = false;
   if (!get_long3(uid_gid, cgroup, ret, p, q))
      return false;
   int parent_tid = (ret >> 32) & 0xffffffffl;
   int rv = ret & 0xffffffffl;

   if (is_err(rv)) exit_errs++;
   int uid = uid_gid & ((1ul<<32)-1);
   int gid = uid_gid >> 32;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer) {
      if (sc == EXECVE_EX)
         eConsumer->exec_exit(sc, sn, clk_ts, tid, pid,
                             parent_tid, rv, uid, gid, cgroup);
      else eConsumer->clone_exit(sc, sn, clk_ts, tid, pid,
                             parent_tid, rv, uid, gid, cgroup);
   }
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_exitids(scname[sc], parent_tid, rv, uid, gid,
                     cgroup, pid, tid, last_pid, last_tid, force_ts, pofp, 
                     is_tampered);
   
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
enter_clone(const char*& p, const char* q) {
   long flags;

   exit_op = false;
   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_clone(CLONE_EX, sn, clk_ts, tid, pid, flags);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
   prt_clone(flags, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_execve(const char*& p, const char* q, bool env_incl) {
   char* fn;
   long flags, fd, id;
   int argc = 0, envc = 0;
   char *argv[MAX_ARG], *envp[MAX_ARG];

   exit_op = false;
   cur_sctype = SC_CRITICAL;
   if (!get_str_long3(fn, flags, fd, id, p, q)) return false;

   int argv_lb = (*p++ & 0xff);
   int argv_hb = (*p++ << 8);
   argc = (argv_hb | argv_lb);

   if (argc > MAX_ARG) return false;

   for (int i=0; i < argc; i++)
      if (!get_string(argv[i], p, q/*, prtInParser? ',' : '\0'*/))
         return false;

   if (argc > 0)
      repl_last_char_strbuf('\0');
   argv[argc] = nullptr;

   if (env_incl) {
      int envc_lb = (*p++ & 0xff);
      int envc_hb = (*p++ << 8);
      envc = (envc_hb | envc_lb);
      if (envc > MAX_ARG) return false;
      for (int i=0; i < envc; i++)
         if (!get_string(envp[i], p, q/*, prtInParser? '\n' : '\0'*/))
            return false;
   }

   if (envc > 0)
      repl_last_char_strbuf('\0');
   envp[envc] = nullptr;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_execveat(EXECVE_EX, sn, clk_ts, tid, pid, fd, id, flags,
                              fn, argv, envp);
   verify_record_crypto_fields(p, q, crypto, is_tampered);
   if (prtInParser)
      prt_execve(fd, id, flags, fn, argv, envp, /*args, envs,*/ pofp, 
                  is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_exit(const char*& p, const char* q) {
   long flags;

   exit_op = false;
   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_exit(EXIT_EN, sn, clk_ts, tid, pid, flags);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_exit(flags, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_exitgrp(const char*& p, const char* q) {
   long flags;

   exit_op = false;
   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->ent_exit(EXITGRP_EN, sn, clk_ts, tid, pid, flags);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_exitgrp(flags, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_finit_module(const char*& p, const char* q) {
   long fd, id, flags, ret;
   char *params;
   cur_sctype = SC_CRITICAL;
   if (!get_str_long4(params, fd, flags, ret, id, p, q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

    if (eConsumer)
      eConsumer->finit_module(FINITMOD_EX, sn, clk_ts, tid, pid, (int)fd, id,
                            params, (int)flags, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if (prtInParser)
      prt_finit_module(params, fd, id, flags, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_init_module(const char*& p, const char * q) {
   char * params;
   long ret;

   if (!get_str_long1(params, ret, p , q))
      return false;
   RecordCryptoFields crypto;
   bool is_tampered = false;
   if (!read_record_crypto_fields(p, q, crypto)) return false;

   if (eConsumer)
      eConsumer->init_module(INITMOD_EX, sn, clk_ts, tid, pid, params, ret);
   verify_record_crypto_fields(p, q, crypto, is_tampered);

   if(prtInParser)
      prt_init_module(params, ret, pofp, is_tampered);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool out_of_sync;
extern bool long_seqnum;

static void
parse_buffer(const char *& p, const char* q, bool ended=false) {
   while (p+8 < q) { // Smallest record is likely >= 8 bytes.
      if (out_of_sync) {
         while (*p != TSMS_EN && p < q) {
            p++;
            skipped++;
         }
         if (p>= q) break;

         // Invariant: p < q && *p == TSMS_EN
         if (!CHK_TSREC(p)) {
            p += MS_BIT_SHIFT/8;
            skipped += 1 + MS_BIT_SHIFT/8;
            continue;
         }

         kernel_ts_msb = GET_TSREC(p);
         p += 8;
         out_of_sync = false;
         tsms_rec1++;
      }

      while (!out_of_sync && (p < q)) {
         // We don't want to start parsing a record and then realize that we don't
         // have a complet record. So, we check for the maximum possible record
         // size, and if we don't have that many bytes left, then we return.
         // But if the input file has already ended, then we continue till the end.

         int max_rec_len = (*p == EXECVE_EN || *p == EXECVEE_EN)? BUFSIZE : 512;
         if (!ended && (p + max_rec_len >= q)) // If the file ended, then we will
            return; // continue to parse till the end, else wait for more content

         bool env_incl = false;
         bool succ = false;
         exit_op = true;  no_entry = true;
         current_rec = p;
         reset_strbuf();

         char sc = *p++;
         if (sc != TS_DIFF && sc != TS_KERN && sc != TSMS_EN) {
            if (use_seqnum) {
               if (long_seqnum) {
                  sn = *(const uint32_t*)p; p += 4;
                  // printf("seq=%u\n", sn);
               }
               else {
                  sn = *(const uint16_t*)p; p += 2;
               }
            }
            if (use_procid) {
               procid = *p; p += 1;
            }
         }
         cur_sctype = SC_DEFAULT;
         switch (sc) {
         case TS_DIFF: {
            tsdiff_rec++;
            uint64_t realtime_ts = *(uint64_t*)p; p += 8;
            uint64_t monotonic_ts = *(uint64_t*)p; p += 8;
            clk_kernel_diff = realtime_ts - monotonic_ts;
            if (eConsumer)
               eConsumer->cur_time(realtime_ts);
            succ = true; exit_op = false; break;
         }

         case TS_KERN: {
            tsdiff_rec++;
            uint64_t prev_tamperwin_start = tamperwin_start;
            tamperwin_start = *(uint64_t*)p;
            if (prev_tamperwin_start > 0)
               tamper_period.addPoint((tamperwin_start 
                                       - prev_tamperwin_start)/1000);
            tamper_windows++;
            tamper_totclag += tamper_thisclag;
            tamperclag.addPoint(tamper_thisclag/1000);
            tamper_thisclag = 0;
            tamper_totilag += tamper_thisilag;
            tamperilag.addPoint(tamper_thisilag/1000);
            tamper_thisilag = 0;
            tamper_totlag += tamper_thislag;
            tamperlag.addPoint(tamper_thislag/1000);
            tamper_thislag = 0;
            p += 8; succ = true; exit_op = false; break;
         }

         case TSMS_EN:
            p--;
            if (!CHK_TSREC(p)) {
               errmsg("Error while parsing a TSMS_EN record", p, q);
               out_of_sync = true;
               goto outer_loop;
            }
            tsms_rec++;
            kernel_ts_msb = GET_TSREC(p);
            p += 8; succ=true; exit_op = false;
            break;
         case CLONE_EN:    succ = enter_clone(p, q); break;
         case CLOSE_EN:    succ = enter_close(p, q); break;
         case EXIT_EN:     succ = enter_exit(p, q); break;
         case EXITGRP_EN:  succ = enter_exitgrp(p, q); break;
         case EXECVEE_EN:  env_incl = true;
         case EXECVE_EN:   // Fall through intentional
                           succ = enter_execve(p, q, env_incl);
                           break;
         case KILL_EN:     succ = enter_kill(p, q); break;
         case FORK_EN:     succ = enter_fork(p, q); break;
         case PTRACE_EN:   succ = enter_ptrace(p, q); break;
         case ACCEPT_EX:   succ = exitt_saddr(ACCEPT_EX, p, q); break;
         case BIND_EX:     succ = exit_bind(p, q); break;
         case CHDIR_EX:    succ = exit_chdir(p, q); break;
         case CHMOD_EX:    succ = exit_chmod(p, q); break;
         case FCHOWN_EX:   succ = exit_fchown(p, q); break;
         case LCHOWN_EX:   succ = exit_chown(p, q); break;
         case MOUNT_EX:    succ = exit_mount(p, q); break;
         case UMOUNT_EX:   succ = exit_umount(p, q); break;
         case CHOWN_EX:    succ = exit_chown(p, q); break;
         case CLONE_EX:    succ = exitt_ids(CLONE_EX, p, q); break;
         case CONNECT_EX:  succ = exit_connect(p, q); break;
         case DUP_EX:      succ = exit_dup(DUP_EX, p, q); break;
         case DUP2_EX:     succ = exit_dup(DUP2_EX, p, q); break;
         case EXECVE_EX:   succ = exitt_ids(EXECVE_EX, p, q); break;
         case FCHDIR_EX:   succ = exit_fchdir(p, q); break;
         case FCHMOD_EX:   succ = exit_fchmod(p, q); break;
         case FORK_EX:     succ = exitt_ids(FORK_EX, p, q); break;
         case FTRUNC_EX:   succ = exit_ftruncate(p, q); break;
         case GETPEER_EX:  succ = exitt_saddr(GETPEER_EX, p, q); break;
         case KILL_EX:     succ = exit_sc(KILL_EX, p, q); break;
         case LINK_EX:     succ = exit_link(p, q); break;
         case MKDIR_EX:    succ = exit_mkdir(p, q); break;
         case MMAP_EX:     succ = exit_mmap(p, q); break;
         case ERR_REP:     succ = error_entry(p, q); break;
         case MPROTECT_EX: succ = exit_mprotect(p, q); break;
         case OPEN_EX:     succ = exit_open(p, q); break;
         case PIPE_EX:     succ = exit_pipe(PIPE_EX, p, q); break;
         case PTRACE_EX:   succ = exit_sc(PTRACE_EX, p, q); break;
         case READ_EX:     succ = exit_read(p, q); break;
         case RECVFROM_EX: succ = exitt_saddr(RECVFROM_EX, p, q); break;
         case RENAME_EX:   succ = exit_rename(p, q); break;
         case RMDIR_EX:    succ = exit_rmdir(p, q); break;
         case SENDTO_EX:   succ = exit_sendto(p, q); break;
         case SETGID_EX:   succ = exit_setgid(p, q); break;
         case SETUID_EX:   succ = exit_setuid(p, q); break;
         case SOCKPAIR_EX: succ = exit_pipe(SOCKPAIR_EX, p, q); break;
         case SYMLINK_EX:  succ = exit_symlink(p, q); break;
         case TRUNC_EX:    succ = exit_truncate(p, q); break;
         case UNLINK_EX:   succ = exit_unlink(p, q); break;
         case WRITE_EX:    succ = exit_write(p, q); break;
         case INITMOD_EX: succ = exit_init_module(p, q); break;
         case FINITMOD_EX:succ = exit_finit_module(p, q); break;
         case MKNOD_EX:    succ = exit_mknod(p, q); break;
         case VMSPLICE_EX: succ = exit_vmsplice(p,q); break;
         default:
            succ = false;
            break;
         }

         if (succ) {
            if (exit_op) {
               exit_rec++;
               scexit_count[(uint8_t)sc]++;
            }
            else {
               entry_rec++;
               if (sc != TS_DIFF && sc != TS_KERN && sc != TSMS_EN)
                  sc_count[(uint8_t)sc]++;
            }
         }
         else {
            err_rec++;
            errmsg("Error while parsing a record", p, q);
            out_of_sync = true;
         }
      }
   outer_loop: ;
   }
}

void parse_rec(const char *p, size_t len) {
   rbuf = p;
   parse_buffer(p, &p[len], true);
}

int infd;

void
parse_stream() {
   const char *p=buf;
   char *q=buf;
   ssize_t nb=-1000000;
   nr=0;

   while (true) {
      // Invariant: unconsumed input starts at p=buf, ends just before q
      long remSpc = PBUFSIZE - (q - buf);
      while (remSpc > min(8192, PBUFSIZE/5)) { // while buffer isn't close to full
         // Invariant on p, q continues to hold, except p is no longer same as buf.
         if ((nb = read(infd, q, remSpc)) <= 0)
            goto done;

         nr += nb;
         q += nb; // Above invariant on p, q still hold; plus, q > p since nb > 0.
         remSpc -= nb;

         parse_buffer(p, q);
      }
      size_t mb = q-p;
      memcpy(buf, p, mb);
      q = buf+mb;
      offset += (p-buf);
      p = buf;
   }

done:
   fprintf(stderr, "eParser: Terminating after reading %ld bytes", nr);
   if (nb < 0) {
      if (nb == -1000000)
         fprintf(stderr, " with UNEXPECTED error.\n");
      else fprintf(stderr, " with an error.\n");
   }
   else fprintf(stderr, ".\n");

   if (p < q)
      parse_buffer(p, q, true);

   delete [] buf;
}

#include "cmdln.C"

void
parser_init() {
   init_scname();
   if (verifyLog) {
      if (!allocate_verifier_signing_keys()) {
         clear_and_free_verifier_signing_keys(verifier_signing_keys_lo);
         clear_and_free_verifier_signing_keys(verifier_signing_keys_hi);
         errexit("Memory allocation failed for key ring");
      }
   }
   if (!online_mode) {
      if (capturefn) {
         if ((infd = open(capturefn, O_RDONLY)) < 0)
            errexit("Unable to open input file");
      }
      else infd = 0; // By default, input read from stdin
   }

   if (prtpfn && *prtpfn) {
      if (*prtpfn != '-') {
         pofp = fopen(prtpfn, "w");
         if (!pofp)
            errexit((string("Unable to open output file ") + prtpfn).data());
      }
      else pofp = stdout;
   }
   else pofp = nullptr;

   if (prtcfn && *prtcfn) {
      if (*prtcfn != '-') {
         cofp = fopen(prtcfn, "w");
         if (!cofp)
            errexit((string("Unable to open output file ") + prtcfn).data());
      }
      else cofp = stdout;
   }
   else cofp = nullptr;

   /* Ignore SIG_INT if not reading from TTY. Also ignore SIGPIPE. It is better
      to wait for the input stream to be closed or a read to return error. */
   if (!isatty(infd))
      signal(SIGINT, SIG_IGN);
   signal(SIGPIPE, SIG_IGN);

   if ((recfn && *recfn) || (prtcfn && *prtcfn)) {
      vector<unsigned> emptyvec;
      if (!ipaddrs)
         ipaddrs = &emptyvec;
      if (!netmasks)
         netmasks = &emptyvec;
      if (!netaddrs)
         netaddrs = &emptyvec;

      ERecorder* er = nullptr;
      if (recfn && *recfn)
         er =  new ERecorder(recfn, *ipaddrs, *netmasks, *netaddrs);
      eConsumer = new EConsumer(lookupProc, summarizeFiles, summarizeEP, 
                                sortByFreq, er);
      if (prtcfn && *prtcfn) {
         auto eprinter = new EPrinter(eConsumer, cofp, true, prt_musec_ts,
                                      lookupProc, lookupProc);
         // If we are looking up proc, then existingsubj and existingobj
         // entries will have useful info. If not, might as well elide them.
         eConsumer->enroll(eprinter, true);
      }
   }
}

void
parser_finish() {
   if (pofp) {
      fputc('\n', pofp);
      fflush(pofp);
   }
   if (eConsumer) {
      eConsumer->finalize();
      eConsumer->prtSum();
      delete eConsumer;
   }
   if(verifyLog) {
      clear_and_free_verifier_signing_keys(verifier_signing_keys_lo);
      clear_and_free_verifier_signing_keys(verifier_signing_keys_hi);
   }

   fprintf(stderr, "############################## Summary from Parser "
           "#############################\n");
   fprintf(stderr,
      "Syscalls enters=%ld, exits=%ld, exits with errors=%ld\n"
      "Records: time=%ld, sync=%ld, corrupted=%ld, truncated str=%ld, data=%ld\n",
      entry_rec-tsdiff_rec-tsms_rec, exit_rec, exit_errs,
      tsms_rec+tsms_rec1, tsdiff_rec, err_rec, trunc_fn, trunc_data);
   prtSortedCounts(sc_count, scname, 255,
      "Scall", "Counts of Syscalls", width);
   prtSortedCounts(scexit_count, scname, 255,
      "Scall", "Syscall exits", width);
   fprintf(stderr, 
      "Out of order records: %ld, average backward slip %g seconds\n",
           n_out_of_order, t_out_of_order/(1e9*n_out_of_order));
   if (skipped >0 || err_rec > 0)
      fprintf(stderr,
         "Read %ld bytes, skipped %ld bytes due to errors\n",
              nr, skipped);

   if (tamper_windows > 0) {
      fprintf(stderr, "************** Tamper window: %g syscalls "
           "(%g critical, %g important)\n",
              tamper_count/(double)tamper_windows,
              tamper_ccount/(double)tamper_windows,
              tamper_icount/(double)tamper_windows);
      fprintf(stderr, "Max tamper window %gms (%gms critical,"
              " %gms important), %ld samples\n", tamper_maxlag/1e6, 
              tamper_maxclag/1e6, tamper_maxilag/1e6, tamper_windows);
            tamper_totclag += tamper_thisclag;
            tamper_thisclag = 0;
      fprintf(stderr, "Avg tamper window %gms (%gms critical,"
              " %gms important)\n",
              tamper_totlag/(1e6*tamper_windows),
              tamper_totclag/(1e6*tamper_windows),
              tamper_totilag/(1e6*tamper_windows));
/*
      cerr << " ------------ Histograms (time in microseconds): --------------\n";
      cerr << "Sampling periods: ";
      tamper_period.print(cerr);
      cerr << "All syscalls: ";
      tamperlag.print(cerr);
      cerr << "Critical: ";
      tamperclag.print(cerr);
      cerr << "Important: ";
      tamperilag.print(cerr);
      cerr << endl;
*/
   if (log_tampered) {
      fprintf(stderr, "************** No of events tampered: %d **************\n",
              n_tampered_events);
      fflush(stderr);
   }

   }
}

int parseCmdLineAndProcInput(int argc, const char* argv[]) {
   parseCmdLine(argc, argv);
   parser_init();
   parse_stream();
   parser_finish();
   return 0;
}
