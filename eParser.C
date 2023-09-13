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

using namespace std;

const char* scname[256];
static FILE *ofp;
enum ScType {SC_DEFAULT, SC_IMPORTANT, SC_CRITICAL};
ScType cur_sctype;

uint64_t max_kernel_ts_clk_kernel_diff;
uint64_t clk_real, clk_kernel; // If synchronization records report both times,
                            // we use these vars; otherwise use just the next var
uint64_t clk_kernel_diff;   // REAL - MONOTONIC clock
uint64_t kernel_ts_msb;     // Just the MS bits from the last Time record
uint64_t kernel_ts;         // The full time stamp for the last record.
uint64_t clk_ts;            // Real time computed from kernel time

long entry_rec, exit_rec, tsms_rec, tsms_rec1, tsdiff_rec, err_rec;
long exit_errs, trunc_fn, trunc_data;
long sc_count[256], scexit_count[256];
bool exit_op, no_ts, no_entry;
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
LongHistogram tamperclag, tamperilag, tamperlag;

const int PBUFSIZE = 1024*8*6;
char *buf = new char[PBUFSIZE];

const char *current_rec;
size_t offset;
uint64_t n_out_of_order, t_out_of_order;

bool print_log, useseqnum, useprocid;
unsigned sn, procid;

/**********************************************************************************
 * Some printing and helper functions
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

string 
countReadable(long count, int w) {
   char ss[21];
   if (count/1000000000>=1) sprintf(ss,"%.*f%s", w, count/1000000000.0, "B");
   else if (count/1000000>=1) sprintf(ss,"%.*f%s", w, count/1000000.0, "M");
   else if (count/1000>=1) sprintf(ss,"%.*f%s", w, count/1000.0, "K");
   else sprintf(ss,"%ld", count);
   return string(ss);
}

string 
countReadable(long c) {
   return countReadable(c, 1);
}

void prtSortedCounts(long count[], const char* const name[], unsigned sz, 
                     const char* title, const char* hdg, int width, FILE* fp) {
   vector<unsigned> idx(sz);
   unsigned cols = width/8;
   unsigned i;

   if (hdg) {
      char s[width+1];
      strncpy(s, hdg, width);
      s[width] = '\0';
      int l = strlen(s);
      int p = (width - l)/2;
      if (l < width-2) {
         for (int j=1; j < p; j++)
            fputc('*', fp);
         fputc(' ', fp);
      }
      fprintf(fp, "%s", s);
      if (l < width-2) {
         fputc(' ', fp);
         if (l+2*p < width) p++;
         for (int j=1; j < p; j++)
            fputc('*', fp);
      }
      fputc('\n', fp);
   }

   iota(idx.begin(), idx.end(), 0);
   sort(idx.begin(), idx.end(),
        [&](unsigned i, unsigned j) { 
           return (count[i] > count[j] || (count[i] == count[j] && i < j)); });

   unsigned nz=sz; unsigned c=0;
   for (; nz > 0; nz--)
      if (count[idx[nz-1]])
         break;

   for (unsigned j=0; j < nz;) {
      fprintf(fp, "%6s: ", title);
      c=1; 
      for (i=j; i < nz; i++) {
         char s[8];
         if (name[idx[i]]) {
            strncpy(s, name[idx[i]], sizeof(s));
            s[7] = '\0';
         }
         else sprintf(s, "#%d", idx[i]);
         fprintf(fp, "%7s ", s);
         if (++c == cols) break;
      }
      fprintf(fp, "\n");
      fprintf(fp, "%6s: ", "Count");
      c=1;
      for (i=j; i < nz; i++) {
         fprintf(fp, "%7s ", countReadable(count[idx[i]], 1).c_str());
         if (++c == cols) break;
      }
      fprintf(fp, "\n");
      j=i+1; c=0;
   }
   if (c != 0) 
      fprintf(fp, "\n");
}


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

static void 
errmsg(const char* msg, const char *p, const char *q) {
   fflush(ofp);
   fprintf(stderr, "***** %s: at offset %ld:\n", msg, offset+(current_rec-buf));
   fwrite(current_rec, p-current_rec, 1, stderr);
   fprintf(stderr, "\n**** Text following error is: ");
   fwrite(p, min(32l, q-p), 1, stderr);
   fprintf(stderr, "\n *******************************************\n");
}

static inline char
hexdigit(char c) {
   if (0 <= c && c < 10)
      return '0'+c;
   else return 'a' + (c-10);
}

static void
bin2str(FILE* fp, const char* path, size_t len) {
   for (unsigned j=0; j <len; j++)
      if (isascii(path[j]))
         fputc(path[j], fp);
      else 
         fprintf(fp, "\\x%c%c", hexdigit((path[j]>>4)&0xf), hexdigit(path[j]&0xf));
}

static void 
init_scname() {
   scname[ACCEPT_EN] = scname[ACCEPT_EX] = "accept";
   scname[BIND_EN] = scname[BIND_EX] = "bind";
   scname[CHDIR_EN] = scname[CHDIR_EX] = "chdir";
   scname[CHMOD_EN] = scname[CHMOD_EX] = "chmod";
   scname[CLONE_EN] = scname[CLONE_EX] = "clone";
   scname[CLOSE_EN] = scname[CLOSE_EX] = "close";
   scname[CONNECT_EN] = scname[CONNECT_EX] = "connect";
   scname[DUP_EX] = "dup";
   scname[DUP2_EX] = "dup2";
   scname[EXECVE_EN] = scname[EXECVE_EX] = scname[EXECVEE_EN] = "execve";
   scname[EXIT_EN] = "exit";
   scname[EXITGRP_EN] = "exitgrp";
   scname[FCHDIR_EN] = scname[FCHDIR_EX] = "fchdir";
   scname[FCHMOD_EN] = scname[FCHMOD_EX] = "fchmod";
   scname[FORK_EN] = scname[FORK_EX] = "fork";
   scname[FTRUNC_EN] = scname[FTRUNC_EX] = "ftruncate";
   scname[GETPEER_EN] = scname[GETPEER_EX] = "getpeername";
   scname[KILL_EN] = scname[KILL_EX] = "kill";
   scname[LINK_EN] = scname[LINK_EX] = "link";
   scname[MKDIR_EN] = scname[MKDIR_EX] = "mkdir";
   scname[MMAP_EN] = scname[MMAP_EX] = "mmap";
   scname[MPROTECT_EN] = scname[MPROTECT_EX] = "mprotect";
   scname[OPEN_EN] = scname[OPEN_EX] = "open";
   scname[PIPE_EN] = scname[PIPE_EX] = "pipe";
   scname[PREAD_EN] = scname[PREAD_EX] = "pread";
   scname[PTRACE_EN] = scname[PTRACE_EX] = "ptrace";
   scname[PWRITE_EN] = scname[PWRITE_EX] = "pwrite";
   scname[READ_EN] = scname[READ_EX] = "read";
   scname[RECVFROM_EN] = scname[RECVFROM_EX] = "recvfrom";
   scname[RENAME_EN] = scname[RENAME_EX] = "rename";
   scname[RMDIR_EN] = scname[RMDIR_EX] = "rmdir";
   scname[SENDTO_EN] = scname[SENDTO_EX] = "sendto";
   scname[SETGID_EN] = scname[SETGID_EX] = "setgid";
   scname[SETUID_EN] = scname[SETUID_EX] = "setuid";
   scname[SOCKPAIR_EN] = scname[SOCKPAIR_EX] = "socketpair";
   scname[SYMLINK_EN] = scname[SYMLINK_EX] = "symlink";
   scname[TRUNC_EN] = scname[TRUNC_EX] = "truncate";
   scname[UNLINK_EN] = scname[UNLINK_EX] = "unlink";
   scname[WRITE_EN] = scname[WRITE_EX] = "write";
   scname[MKNOD_EN] = scname[MKNOD_EX] = "mknod";
   scname[FI_MODULE_EN] = scname[FI_MODULE_EX] = "finit_module" ;
   scname[I_MODULE_EN] = scname[I_MODULE_EX] = "init_module";
   scname[SPLICE_EN] = scname[SPLICE_EX]  = "splice";
   scname[VMSPLICE_EN] = scname[VMSPLICE_EX] = "vmsplice";
   scname[TEE_EN] = scname[TEE_EX] = "tee";
   scname[SOCKET_EN] = scname[SOCKET_EX] = "socket";
}

/******************************************************************************
* Printing-related helper functions.                                          *
******************************************************************************/

static void 
prttspid(uint64_t ts, int p, uint16_t sn, uint8_t procid) {
   static uint64_t last_ts;

   static char c[64];
   int j=63;
   static int ts_idx;
   const int pid_idx=47;
   if (useseqnum)
      ts = ts/1000000;
   else ts = ts/10000;

   if (pid == last_tid) 
      j = pid_idx;
   else {
      c[--j] = '\0';
      c[--j] = ' ';
      c[--j] = ':';
      while (p > 0) {
         unsigned x = p % 10;
         p = p/10;
         c[--j] = x + '0';
      }
      c[--j] = '=';
      c[--j] = 'd';
      c[--j] = 'i';
      c[--j] = 'p';
      while (j > pid_idx+1)
         c[--j] = ' ';
      c[--j] = ':';
   }

   if (useseqnum) {
      unsigned x = sn % 10;
      sn = sn/10;
      c[--j] = x + '0';
      x = sn % 10;
      sn = sn/10;
      c[--j] = x + '0';
      x = sn % 10;
      sn = sn/10;
      c[--j] = x + '0';
      x = sn % 10;
      sn = sn/10;
      c[--j] = x + '0';
      x = sn;
      c[--j] = x + '0';
      c[--j] = ':';
   }

   if (useprocid) {
      c[--j] = hexdigit(procid&0xf);
      c[--j] = hexdigit((procid>>4)&0xf);
      c[--j] = ':';
   }

   if (ts == last_ts) 
      j = ts_idx;
   else {
      last_ts = ts;
      int l=0;
      while (ts > 0) {
         unsigned x = ts % 10;
         ts = ts/10;
         c[--j] = x + '0';
         if (useseqnum) {
            if (++l == 3)
               c[--j] = '.';
         }
         else if (++l == 5)
            c[--j] = '.';
      }
      c[--j] = '\n';
      ts_idx = j;
   }
   fputs(&c[ts_idx], ofp);
}

// %%%% Most overhead in eParse comes from printing --- 80% or more. It used to 
// %%%% be more like 95%, then a few heavy hitters --- just a few lines of code
// %%%% altogether --- were hand-tweaked to improve performance by more than 2x.
// %%%% There is still scope for improvement, but the easy stuff is done.

static void
prt_ts_and_pid() {
   // @@@@ About 70% of the runtime for printing is from just the next line!
   //fprintf(ofp, "%ld: pid=%d: ", ts, pid);
   prttspid(clk_ts, pid, sn, procid);
   if (tid != pid)
      fprintf(ofp, "tid=%u: ", tid);
}

static void
prt_open(long fd, const char* fn, long fl, long md, long ret) {
   if (fd != AT_FDCWD)
      fprintf(ofp, "open(at=%lu, file=\"%s\", flags=%lx, mode=%#lo) ret=%ld", 
              fd, fn, fl, md, ret);
   else fprintf(ofp, "open(file=\"%s\", flags=%lx, mode=%#lo) ret=%ld", 
                fn, fl, md, ret);
}

static void
prt_ret(uint8_t sc, long ret) {
   if (pid != last_pid || tid != last_tid)
      fprintf(ofp, "%s ret=%ld", scname[sc], ret);
   else fprintf(ofp, " ret=%ld", ret);
}

static void
prt_exitids(uint8_t sc, long ret, int uid, int gid, long cgroup) {
   if (pid != last_pid || tid != last_tid)
      fprintf(ofp, "%s ret=%ld uid=%d gid=%d cgroup=%ld", 
              scname[sc], ret, uid, gid, cgroup);
   else fprintf(ofp, " ret=%ld uid=%d gid=%d cgroup=%ld", 
              ret, uid, gid, cgroup);
}

static void
prt_dup(char sc, long fd, long ret) {
   fprintf(ofp, "%s(fd=%ld) ret=%ld", scname[(unsigned)sc], fd, ret);
}

static void
prt_fchdir(long fd) {
   fprintf(ofp, "fchdir(fd=%lu)", fd);
}

static void
prt_fchmod(long fd, long mode) {
   fprintf(ofp, "fchmod(fd=%lu, mode=%#lo)", fd, mode);
}

static void
prt_read(long fd, long ret) {
   fprintf(ofp, "read(fd=%lu) ret=%ld", fd, ret);
}

static void
prt_write(long fd, long ret) {
   fprintf(ofp, "write(fd=%lu) ret=%ld", fd, ret);
}

static void
prt_close(long fd, long unrep_rd, long unrep_wr) {
   if (unrep_rd) {
      prt_read(fd, unrep_rd);
      prt_ts_and_pid();
   }
   if (unrep_wr) {
      prt_write(fd, unrep_wr);
      prt_ts_and_pid();
   }
   char c[32];
   int j=32;
   c[--j] = '\0';
   c[--j] = ')';
   while (fd > 0) {
      unsigned x = fd % 10;
      fd = fd/10;
      c[--j] = x + '0';
   }
   fputs("close(fd=", ofp);
   fputs(&c[j], ofp);
}

static void
prt_pipe_spair(uint8_t sc, long ret) {
   fputs(sc==PIPE_EX? "pipe" : "socketpair", ofp);
   if (is_err(ret))
      fprintf(ofp, "() ret=%ld", ret);
   else fprintf(ofp, "() fd1=%d fd2=%d", (int)(ret&0xffffffff), (int)(ret>>32));
}

static void
print_saddr(uint8_t *sa, uint64_t len) {
   if (len < sizeof(sa_family_t)) {
      fprintf(ofp, "invalid: ");
      return;
   }

   // for (int j=0; j < len; j++)
   //   fprintf(ofp, "%d.", sa[j]);
   // fprintf(ofp, "\n");

   saddr_t& saddr = *(saddr_t*)sa;
   char s[128], pt[16];

   switch (saddr.sun.sun_family) {
   case AF_UNSPEC:
      fprintf(ofp, "unspec:");
      break;

   case AF_LOCAL: {
      const struct sockaddr_un& un = saddr.sun;
      fprintf(ofp, "unix:");
      if (len == sizeof(sa_family_t))
         fprintf(ofp, "unnamed");
      else if (un.sun_path[0] == '\0') {
        // These are special endpoints that don't create a file.
        // Don't ignore, thinking it is an (invalid) null string.
        bin2str(ofp, un.sun_path, len-sizeof(sa_family_t));
      }
      else fprintf(ofp, "%s", (char*)un.sun_path);
      //fputc(' ', ofp);
      break;
   }

   case AF_INET: {
      const struct sockaddr_in& in = saddr.sin;
      unsigned ip = in.sin_addr.s_addr;
      unsigned short port = ntohs(in.sin_port);
      fprintf(ofp, "IP4:%d.%d.%d.%d:%d", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff,
              ip>>24, port);
      break;
   }

   case AF_NETLINK: {
      const struct sockaddr_nl& nl = saddr.snl;
      fprintf(ofp, "netlink:%d/%x", nl.nl_pid, nl.nl_groups);
      break;
   }

   case AF_INET6: {
      getnameinfo((struct sockaddr*)&saddr.sin6, sizeof(saddr.sin6), 
                  s, sizeof(s), pt, sizeof(pt), NI_NUMERICHOST|NI_NUMERICSERV);
      fprintf(ofp, "IP6:%s:%s", s, pt);
      break;
   }

   default:
      fprintf(ofp, "unsupported:");
      break;
   }
}

static void
prt_saddr(uint8_t sc, long fd, long ret, uint8_t *saddr, unsigned slen)  {
   fprintf(ofp, "%s(fd=%lu) ret=%ld", scname[sc], fd, ret);
   if (slen > 0) {
      fprintf(ofp, " endpoint=");
      print_saddr(saddr, slen);
   }
}

static void
prt_connect(long fd, long ret, uint8_t *saddr, unsigned slen)  {
   fprintf(ofp, "connect(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen);
   fprintf(ofp, ") ret=%ld", ret);
}

static void
prt_bind(long fd, uint8_t *saddr, unsigned slen)  {
   fprintf(ofp, "bind(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen);
   fputc(')', ofp);
}

static void
prt_sendto(long fd, uint8_t *saddr, unsigned slen, long ret)  {
   fprintf(ofp, "sendto(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen);
   fprintf(ofp, ") ret=%ld", ret);
}

static void
prt_truncate(const char* fn, long len) {
   fprintf(ofp, "truncate(file=\"%s\", len=%ld)", fn, len);
}

static void
prt_ftruncate(long fd, long len) {
   fprintf(ofp, "ftruncate(fd=%lu, len=%ld)", fd, len);
}

static void
prt_mmap(long addr, long len, int prot, long flags) {
      fprintf(ofp, "mmap(addr=%lx, len=%ld, prot=%d, flags=%lx)", 
              addr, len, prot, flags);
}

static void
prt_mmap_ret(long fd, long ret) {
   if (pid != last_pid || tid != last_tid)
      fprintf(ofp, "mmap fd=%ld ret=%lx", fd, ret);
   else fprintf(ofp, " fd=%ld ret=%lx", fd, ret);
}

static void
prt_mprotect(long addr, long len, long prot, long ret) {
   fprintf(ofp, "mprotect(addr=%lx, len=%ld, prot=%lx) ret=%ld", 
           addr, len, prot, ret);
}

static void
prt_unlink(long fd, const char* fn) {
   fprintf(ofp, "unlink(");
   if (fd != AT_FDCWD)
      fprintf(ofp, "at=%lu, ", fd);
   fprintf(ofp, "file=\"%s\")", fn);
}

static void
prt_mkdir(long fd, const char *fn, long mode) {
   fprintf(ofp, "mkdir(");
   if (fd != AT_FDCWD)
      fprintf(ofp, "at=%lu, ", fd);
   fprintf(ofp, "file=\"%s\", mode=%#lo)", fn, mode);
}
//Added to print mknod 
static void
prt_mknod(long fd, const char *fn, long mode, long dev) {
   //fprintf(ofp,"file descriptor-test: %ld", fd);
   fprintf(ofp, "mknod(");
   if (fd != AT_FDCWD)
      fprintf(ofp, "at=%lu, ", fd);
   fprintf(ofp, "file=\"%s\", mode=%#lo, dev=%ld)", fn, mode, dev);
}
static void 
prt_chmod(long fd, const char *fn, long mode) {
   fprintf(ofp, "chmod(");
   if (fd != AT_FDCWD)
      fprintf(ofp, "at=%lu, ", fd);
   fprintf(ofp, "file=\"%s\", mode=%#lo)", fn, mode);
}

static void
prt_rmdir(const char* fn) {
   fprintf(ofp, "rmdir(file=\"%s\")", fn);
}

static void
prt_chdir(const char *fn) {
   fprintf(ofp, "chdir(file=\"%s\")", fn);
}

static void
prt_link(long fd1, long fd2, const char *s1, const char *s2, long flags) {
   fprintf(ofp, "link(");
   if (fd1 != AT_FDCWD || fd2 != AT_FDCWD)
      fprintf(ofp, "src=\"%s\", at=%lu, dst=\"%s\", at=%lu, flags=%lx)", 
              s1, fd1, s2, fd2, flags);
   else fprintf(ofp, "src=\"%s\", dst=\"%s\")", s1, s2);
}

static void
prt_rename(long fd1, long fd2, const char *s1, const char *s2, long flags) {
   fprintf(ofp, "rename(");
   if (fd1 != AT_FDCWD || fd2 != AT_FDCWD)
      fprintf(ofp, "src=\"%s\", at=%lu, dst=\"%s\", at=%lu", 
              s1, fd1, s2, fd2);
   else fprintf(ofp, "src=\"%s\", dst=\"%s\"", s1, s2);
   if (flags != 0) fprintf(ofp, ", flags=%lx", flags);
   fprintf(ofp, ")");
}

static void
prt_symlink(long fd, const char *s1, const char *s2) {
   fprintf(ofp, "symlink(src=\"%s\", dst=\"%s\"", s1, s2);
   if (fd != AT_FDCWD)
      fprintf(ofp, ", at=%lu", fd);
   fprintf(ofp, ")");
}

static void
prt_kill(int pid, int tid, int sig) {
   if (pid == tid) 
      fprintf(ofp, "kill(pid=%d, sig=%d)", pid, sig);
   else if (pid == 0)
      fprintf(ofp, "kill(tid=%d, sig=%d)", tid, sig);
   else fprintf(ofp, "kill(pid=%d, tid=%d, sig=%d)", pid, tid, sig);
}

static void
prt_ptrace(int pid, long req) {
   fprintf(ofp, "ptrace(req=%lx, pid=%d)", req, pid);
}

static void
prt_setuid(int euid, int ruid, int suid) {
   fprintf(ofp, "setuid(euid=%d", euid);
   if (ruid != -1)
      fprintf(ofp, ", ruid=%d", ruid);
   if (suid != -1)
      fprintf(ofp, ", suid=%d", suid);
   fprintf(ofp, ")");
}

static void
prt_setgid(int egid, int rgid, int sgid)  {
   fprintf(ofp, "setgid(egid=%d", egid);
   if (rgid != -1)
      fprintf(ofp, ", rgid=%d", rgid);
   if (sgid != -1)
      fprintf(ofp, ", sgid=%d", sgid);
   fprintf(ofp, ")");
}

static void
prt_fork() {
   fprintf(ofp, "fork()");
}

static void
prt_clone(long flags) {
   fprintf(ofp, "clone(flags=%lx)", flags);
}

static void
prt_execve(long fd, long fl, const char *fn, const char *args, const char *envs) {
   if (fd == AT_FDCWD && fl == 0)
      fprintf(ofp, "execve(file=\"%s\", ", fn);
   else fprintf(ofp, "execve(at=%lu, flags=%lx, file=\"%s\", ", fd, fl, fn);
   
   fprintf(ofp, "argv=%s env=%s", args, envs);
   fprintf(ofp, ")");
}

static void
prt_exit(long flags) {
   fprintf(ofp, "exit(code=%lx)", flags);
}

static void
prt_exitgrp(long flags) {
   fprintf(ofp, "exitgrp(code=%lx)", flags);
}

static void
prt_finit_module(const char * usr_args, long fd, long flags){
   fprintf(ofp, "finit_module(");
   fprintf(ofp, "fd=%lu, ", fd);
   fprintf(ofp, "uargs=\"%s\", flags=%lx", usr_args, flags);
   fprintf(ofp, ")");

}

static void
prt_init_module(const char * usr_args, const char *data, long slen ){
   fprintf(ofp,"init_module(");
   if(slen > 0)
   fprintf(ofp,"umode=\"%s\",",data);
   fprintf(ofp," uargs=%s",usr_args);
   fprintf(ofp, ")");
}

static void
prt_splice(long off_in, long off_out, long dlen, int fd_in,
           int fd_out, int flags){
   fprintf(ofp, "splice(");
   fprintf(ofp, "len=%lu, fd_in=%d, fd_out=%d, flags=%d", 
                                       dlen, fd_in, fd_out, flags);
   fprintf(ofp, ")");

}

static void
prt_vmsplice( long fd, long flags){
   fprintf(ofp,"vmsplice(");
   fprintf(ofp,"fd=%lo,",fd);
   fprintf(ofp," flags=%lo", flags);
   fprintf(ofp, ")");
}

static void
prt_tee(long fd_in, long fd_out,long dlen, int flags){
   fprintf(ofp, "tee(");
    fprintf(ofp, "len=\"%lu\", fd_in=%lu, fd_out=%lu, flags=%d)", 
                                       dlen, fd_in, fd_out, flags);
   fprintf(ofp, ")");

}
//Added to print for socket syscalls 
static void
prt_socket(long family, long type, long protocol){
   fprintf(ofp, "socket(");
   fprintf(ofp, "Family=%lu, ", family);
   fprintf(ofp, "Type=%lu, prot=%lu", type, protocol);
   fprintf(ofp, ")");

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
   if (exit_op && no_ts) { // No timestamp to read
      if (p+1 >= q) return false;
   }
   else {         // Read and process timestamp
      if (p+5 >= q) return false;

      uint64_t last_kernel_ts = kernel_ts;
#ifdef FULL_TIME
      kernel_ts = *(const uint64_t*)p; p+= 8;
      uint64_t ts_lsb = LS_BITS(kernel_ts);
      if (kernel_ts != kernel_ts_msb + ts_lsb)
         fprintf(stderr, "diff: %ld\n", (long)(kernel_ts - kernel_ts_msb - ts_lsb));
#else
      uint32_t ts_lsb = *(const int*)p; p+= 3;
      ts_lsb = LS_BITS(ts_lsb);
      kernel_ts = kernel_ts_msb + ts_lsb;
#endif
      if (kernel_ts < clk_kernel) {
         max_kernel_ts_clk_kernel_diff = max(max_kernel_ts_clk_kernel_diff, clk_kernel-kernel_ts);
         if (cur_sctype == SC_CRITICAL) {
            tamper_ccount++;
            tamper_thisclag = max(tamper_thisclag, clk_kernel - kernel_ts);
            tamper_maxclag = max(tamper_maxclag, clk_kernel - kernel_ts);
         }
         else if (cur_sctype == SC_IMPORTANT) {
            tamper_icount++;
            tamper_thisilag = max(tamper_thisilag, clk_kernel - kernel_ts);
            tamper_maxilag = max(tamper_maxilag, clk_kernel - kernel_ts);
         }
         tamper_count++;
         tamper_thislag = max(tamper_thislag, clk_kernel - kernel_ts);
         tamper_maxlag = max(tamper_maxlag, clk_kernel - kernel_ts);
      }
      clk_ts = kernel_ts + clk_kernel_diff;
      if (kernel_ts < last_kernel_ts) {
         uint64_t backdrift = (last_kernel_ts - kernel_ts);
         if (backdrift > 1e10) 
            fprintf(stderr, "Backdrift by %g seconds\n", backdrift/1e9);
         if (backdrift < 1e11) {
            n_out_of_order++;
            t_out_of_order += backdrift;
         }
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

   if (print_log) {
      if (no_entry || !exit_op || pid != last_pid || tid != last_tid)
         prt_ts_and_pid();
   }
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
get_long3int(long& a1, long& a2, long& a3, int& a4, const char*& p, const char* q) {
   if (!get_long3(a1, a2, a3, p, q)) return false;
   if (p+4 >= q) return false;
   a4 = *(int*)p; p+= 4;
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
get_str_long0(char*& s, const char*& p, const char* q) {
   if (!get_ts_and_widths(p, q)) return false;
   if (!get_string(s, p, q)) return false;
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
get_str2_long1(char*& s1, char*& s2, long& a1,
               const char*& p, const char* q) {
   if (!get_long1(a1, p, q)) return false;
   if (!get_string(s1, p, q)) return false;
   if (!get_string(s2, p, q)) return false;
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
get_data(uint8_t*& d, unsigned& dlen, const char*& p, const char* q) {
   dlen = (uint8_t)*p;
   d = (uint8_t*)++p; // skip length field
   if (dlen > MAX_DLEN) trunc_data++;
   if (p+dlen >= q) return false;
   p += dlen;
   return true;
}

static bool
get_data_long1(uint8_t*& d, unsigned& dlen, long& a1, const char*& p, 
               const char* q) {
   if (!get_long1(a1, p, q)) return false;
   if (!get_data(d, dlen, p, q)) return false;
   return true;
}

static bool
get_data_long2(uint8_t*& d, unsigned& dlen, long& a1, long &a2,
               const char*& p, const char* q) {
   if (!get_long2(a1, a2, p, q)) return false;
   if (!get_data(d, dlen, p, q)) return false;
   return true;
}

/**********************************************************************************
 * Functions to parse syscalls and arguments
 *********************************************************************************/
static bool
exit_open(const char*& p, const char* q) {
   char* fn;
   long md_fl;
   long at, fl, md;
   long ret;

   exit_op = true; no_ts = false; no_entry = true;
   if (!get_str_long3(fn, md_fl, at, ret, p, q))
      return false;

   md = md_fl >> 32;
   fl = md_fl & 0xffffffff;

   if (print_log) 
      prt_open(at, fn, fl, md, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_sc(uint8_t sc, const char*& p, const char* q) {
   long ret;
   exit_op = true;
   if (!get_long1(ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;

   // Close return value is not important. Let us not wait for it.
   if (print_log)
      prt_ret(sc, ret);
   if (*p != '\n')
    errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool
exitt_sc(uint8_t sc, const char*& p, const char* q) {
   no_ts = false;
   return exit_sc(sc, p, q);
}

static bool 
enter_close(const char*& p, const char* q) {
   long fd, unrep_read, unrep_write;

   if (!get_long3(fd, unrep_read, unrep_write, p, q))
      return false;

   // Close return value is not important. Let us not wait for it.
   if (print_log) {
      prt_close(fd, unrep_read, unrep_write);
   }
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
exit_dup(char sc, const char*& p, const char* q) {
   long fd, ret;

   exit_op = true; no_ts = false; no_entry = true;
   if (!get_long2(fd, ret, p, q))
      return false;

   if (print_log)
      prt_dup(sc, fd, ret);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_pipe(uint8_t sc, const char*& p, const char* q) {
   long ret;
   exit_op = true; no_ts = false; no_entry = true;
   if (!get_long1(ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;

   if (print_log)
      prt_pipe_spair(sc, ret);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool 
exit_read(const char*& p, const char* q) {
   long fd, ret;
   exit_op = true; no_ts = false; no_entry = true;

   if (!get_long2(fd, ret, p, q))
         return false;

   if (print_log) 
      prt_read(fd, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exitt_saddr(uint8_t sc, const char*& p, const char* q) {
   long ret, fd;
   uint8_t *saddr;
   unsigned slen=0;

   exit_op = true; no_ts = false;  no_entry = true;
   if (!get_data_long2(saddr, slen, fd, ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;

   if (print_log)
      prt_saddr(sc, fd, ret, saddr, slen);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool 
exit_connect(const char*& p, const char* q) {
   long fd, ret;
   uint8_t* saddr;
   unsigned slen=0;
   exit_op = true; no_ts = false; no_entry = true;

   if (!get_data_long2(saddr, slen, fd, ret, p, q))
      return false;

   if (print_log) 
      prt_connect(fd, ret, saddr, slen);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_bind(const char*& p, const char* q) {
   long fd;
   uint8_t* saddr;
   unsigned slen=0;

   if (!get_data_long1(saddr, slen, fd, p, q))
      return false;

  if (print_log) 
      prt_bind(fd, saddr, slen);
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
   exit_op = true; no_ts = false; no_entry = true;

   if (!get_data_long2(saddr, slen, fd, ret, p, q))
      return false;

  if (print_log) 
      prt_sendto(fd, saddr, slen, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
exit_write(const char*& p, const char* q) {
   long fd, ret;

   exit_op = true; no_ts = false; no_entry = true;
   if (!get_long2(fd, ret, p, q))
         return false;

   if (print_log) 
      prt_write(fd, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_truncate(const char*& p, const char* q) {
   char* fn;
   long len;

   if (!get_str_long1(fn, len, p, q))
      return false;

   if (print_log)
      prt_truncate(fn, len);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_ftruncate(const char*& p, const char* q) {
   long len, fd;

   if (!get_long2(fd, len, p, q))
      return false;

   if (print_log)
      prt_ftruncate(fd, len);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_mmap(const char*& p, const char* q) {
   long addr, len;
   long flags;
   long prot;

   // Uncomment the next line *if* LOG_MMAPALL is *NOT* enabled in the log
   //cur_sctype = SC_IMPORTANT;
   if (!get_long3(addr, len, flags, p, q))
      return false;

   prot = flags & 0x7;
   flags = (((uint64_t)flags) >> 32);

   if (print_log)
      prt_mmap(addr, len, prot, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exit_mmap(const char*& p, const char* q) {
   long fd, ret;
   exit_op = true;
   if (!get_long2(fd, ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;

   if (print_log)
      prt_mmap_ret(fd, ret);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool 
exit_mprotect(const char*& p, const char* q) {
   long addr, len, prot, ret;

   // Uncomment the next line *if* LOG_MMAPALL is *NOT* enabled in the log
   //cur_sctype = SC_IMPORTANT;

   exit_op = true; no_ts = false; no_entry = true;
   if (!get_long3(addr, len, ret, p, q))
      return false;

   prot = ret >> 32;
   ret = ((int)(ret & 0xffffffff));

   if (print_log)
      prt_mprotect(addr, len, prot, ret);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_unlink(const char*& p, const char* q) {
   char* fn;
   long fd;

   cur_sctype = SC_IMPORTANT;
   if (!get_str_long1(fn, fd, p, q))
      return false;

   if (print_log) 
      prt_unlink(fd, fn);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_mkdir(const char*& p, const char* q) {
   char* fn;
   long fd, mode;

   if (!get_str_long2(fn, fd, mode, p, q))
      return false;

   if (print_log) 
      prt_mkdir(fd, fn, mode);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}
/*******************************************************************************
 * Code added for adding Parser for mknod syscall*
 * *****************************************************************************/
static bool
enter_mknod(const char*& p, const char* q) {
   char* fn;
   long fd, mode, dev;

   if (!get_str_long3(fn, fd, mode, dev, p, q))
      return false;

   if (print_log) 
      prt_mknod(fd, fn, mode, dev);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_rmdir(const char*& p, const char* q) {
   char* fn;

   if (!get_str_long0(fn, p, q))
      return false;

  if (print_log)
      prt_rmdir(fn);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_chdir(const char*& p, const char* q) {
   char* fn;

   cur_sctype = SC_IMPORTANT;
   if (!get_str_long0(fn, p, q))
      return false;

   if (print_log)
      prt_chdir(fn);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_fchdir(const char*& p, const char* q) {
   long fd;

   cur_sctype = SC_IMPORTANT;
   if (!get_long1(fd, p, q))
      return false;

   if (print_log)
      prt_fchdir(fd);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_link(const char*& p, const char* q) {
   char *s1, *s2;
   long ofd, nfd, flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long3(s1, s2, ofd, nfd, flags, p, q))
      return false;

   if (print_log) 
      prt_link(ofd, nfd, s1, s2, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_symlink(const char*& p, const char* q) {
   char *s1, *s2;
   long fd;

   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long1(s1, s2, fd, p, q))
      return false;

   if (print_log) 
      prt_symlink(fd, s1, s2);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_rename(const char*& p, const char* q) {
   char *s1, *s2;
   long ofd, nfd, flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_str2_long3(s1, s2, ofd, nfd, flags, p, q))
      return false;

   if (print_log) 
      prt_rename(ofd, nfd, s1, s2, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

/*******************************************************************************
 * Code added for adding Parser for SPLICE,VMSPICE and TEE syscall*
 * *****************************************************************************/
static bool
enter_splice(const char*& p, const char* q) {
   
   long fd_in, fd_out, len;
   int flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3int( len, fd_in, fd_out, flags, p, q))
      return false;

   if (print_log)
      prt_splice(0, 0, len, fd_in, fd_out, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;

}

static bool
enter_vmsplice(const char*& p, const char* q) {
   long fd, flags ;

   cur_sctype = SC_IMPORTANT;
   if (!get_long2(fd, flags, p, q))
      return false;

   if (print_log)
      prt_vmsplice(fd, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;

}

static bool
enter_tee(const char*& p, const char* q) {
   long fdin, fdout, len;
   int flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3int(fdin, fdout, len, flags, p, q))
      return false;

   if (print_log)
      prt_tee(fdin, fdout, len, flags);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;

}

static bool
enter_socket(const char*& p, const char* q) {
   long family, type, protocol;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3(family, type, protocol, p, q))
      return false;

   if (print_log)
      prt_socket(family, type, protocol);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;

}
static bool 
enter_kill(const char*& p, const char* q) {
   long pid_tgid, sig;

   cur_sctype = SC_CRITICAL;
   if (!get_long2(pid_tgid, sig, p, q))
      return false;
   int pid1 = pid_tgid >> 32;
   int tid1 = pid_tgid & ((1ul << 32)-1);

   if (print_log) 
      prt_kill(pid1, tid1, (int)sig);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_ptrace(const char*& p, const char* q) {
   long pid1, req;

   cur_sctype = SC_CRITICAL;
   if (!get_long2(req, pid1, p, q))
      return false;

   if (print_log)
      prt_ptrace((int)pid1, req);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_chmod(const char*& p, const char* q) {
   char* fn;
   long fd, mode;

   cur_sctype = SC_IMPORTANT;
   if (!get_str_long2(fn, mode, fd, p, q))
      return false;

   if (print_log) 
      prt_chmod(fd, fn, mode);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_fchmod(const char*& p, const char* q) {
   long fd, mode;

   cur_sctype = SC_IMPORTANT;
   if (!get_long2(fd, mode, p, q))
      return false;

   if (print_log)
      prt_fchmod(fd, mode);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_setuid(const char*& p, const char* q) {
   long ruid, euid, suid;

   cur_sctype = SC_CRITICAL;
   if (!get_long3(ruid, euid, suid, p, q))
      return false;

   if (print_log) 
      prt_setuid((int)euid, (int)ruid, (int)suid);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool 
enter_setgid(const char*& p, const char* q) {
   long rgid, egid, sgid;

   cur_sctype = SC_IMPORTANT;
   if (!get_long3(rgid, egid, sgid, p, q))
      return false;

   if (print_log)
      prt_setgid((int)egid, (int)rgid, (int)sgid);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_fork(const char*& p, const char* q) {
   cur_sctype = SC_IMPORTANT;
   if (!get_ts_and_widths(p, q)) return false;
   if (print_log)
      prt_fork();

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
exitt_ids(uint8_t sc, const char*& p, const char* q) {
   long ret;
   long uid_gid, cgroup;

   exit_op = true; no_ts = false;
   if (!get_long3(uid_gid, cgroup, ret, p, q))
      return false;
   if (is_err(ret)) exit_errs++;
   int uid = uid_gid & ((1ul<<32)-1);
   int gid = uid_gid >> 32;

   if (print_log)
      prt_exitids(sc, ret, uid, gid, cgroup);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // We include a newline at the end of records, skip it
   return true;
}

static bool 
enter_clone(const char*& p, const char* q) {
   long flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;

   if (print_log)
      prt_clone(flags);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_execve(const char*& p, const char* q, bool env_incl) {
   char* fn;
   long flags, fd;
   int argc, envc=0;
   char *argv[32], *envp[32];

   cur_sctype = SC_CRITICAL;
   if (!get_str_long2(fn, flags, fd, p, q)) return false;

   argc = *p++;
   if (argc >= 32) return false;
   
   for (int i=0; i < argc; i++)
      if (!get_string(argv[i], p, q, print_log? ',' : 1))
         return false;

   char *args;
   if (argc > 0) {
      args = argv[0];
      repl_last_char_strbuf('\0');
   }
   else args = copy2strbuf(p, 0, '\0');
   argv[argc] = nullptr;

   if (env_incl) {
      envc = *p++;
      if (envc >= 32) return false;
      for (int i=0; i < envc; i++)
         if (!get_string(envp[i], p, q, print_log? '\n' : 1)) 
            return false;
   }

   const char *envs;
   if (envc > 0) {
      envs = envp[0];
      repl_last_char_strbuf('\0');
   }
   else envs =  copy2strbuf(p, 0, '\0');
   envp[envc] = nullptr;

   if (print_log) 
      prt_execve(fd, flags, fn, args, envs);

   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_exit(const char*& p, const char* q) {
   long flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;

   if (print_log)
      prt_exit(flags);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

static bool
enter_exitgrp(const char*& p, const char* q) {
   long flags;

   cur_sctype = SC_IMPORTANT;
   if (!get_long1(flags, p, q))
      return false;

   if (print_log)
      prt_exitgrp(flags);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}
/*******************************************************************************
 * Code added for adding Parser for finit_module syscall*
 * *****************************************************************************/
static bool
enter_finit_module(const char*& p, const char* q){
   long fd,flags;
   char * usr_args;
   cur_sctype = SC_CRITICAL;
   if (!get_str_long2(usr_args, fd, flags, p, q))
      return false;
   if (print_log)
      prt_finit_module(usr_args, fd, flags);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;
}

/*******************************************************************************
 * Code added for adding Parser for init_module syscall*
 * *****************************************************************************/

static bool
enter_init_module(const char*& p, const char * q){
   char * usr_args;
   char * data;
   long slen=0;
   // if (!get_str_data_long0(usr_args, data, slen, p , q))
   //    return false;
   if (!get_str2_long1(usr_args, data, slen, p , q))
      return false;
   if(print_log)
      prt_init_module(usr_args, data, slen);
   if (*p != '\n')
      errmsg("Missing newline", p, q);
   p++; // Skip the trailing newline character at the end of the record
   return true;

}

static bool out_of_sync;

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

         int max_rec_len = (*p == EXECVE_EN || *p == EXECVEE_EN)? 8250 : 512;
         if (!ended && (p + max_rec_len >= q)) // If the file ended, then we will
            return;                            // continue to parse till the end.
                                               // If not, read the whole msg.
         bool env_incl = false;
         bool succ = false; 
         exit_op = false; no_ts = true; no_entry = false;
         current_rec = p;
         reset_strbuf();

         char sc = *p++;
         if (sc != TS_DIFF && sc != TS_KERN && sc != TSMS_EN) {
            if (useseqnum) {
               sn = *(const uint16_t*)p; p += 2;
            }
            if (useprocid) {
               procid = *p; p += 1;
            }
         }
         cur_sctype = SC_DEFAULT;
         switch (sc) {
         case TS_DIFF: 
            tsdiff_rec++;
            clk_kernel_diff = *(uint64_t*)p;
            p += 8; succ = true; break;

         case TS_KERN: 
            tsdiff_rec++;
            clk_kernel = *(uint64_t*)p;
            tamper_windows++;
            tamper_totclag += tamper_thisclag;
            tamperclag.addPoint(tamper_thisclag/1e3);
            tamper_thisclag = 0;
            tamper_totilag += tamper_thisilag;
            tamperilag.addPoint(tamper_thisilag/1e3);
            tamper_thisilag = 0;
            tamper_totlag += tamper_thislag;
            tamperlag.addPoint(tamper_thislag/1e3);
            tamper_thislag = 0;
            p += 8; succ = true; break;

         case TSMS_EN:
            p--;
            if (!CHK_TSREC(p)) {
               out_of_sync = true; 
               goto outer_loop;
            }
            tsms_rec++;
            kernel_ts_msb = GET_TSREC(p);
            p += 8; succ=true;
            break;

         case BIND_EN:     succ = enter_bind(p, q); break;
         case CHDIR_EN:    succ = enter_chdir(p, q); break;
         case CHMOD_EN:    succ = enter_chmod(p, q); break;
         case CLONE_EN:    succ = enter_clone(p, q); break;
         case CLOSE_EN:    succ = enter_close(p, q); break;
         case EXIT_EN:     succ = enter_exit(p, q); break;
         case EXITGRP_EN:  succ = enter_exitgrp(p, q); break;
         case EXECVEE_EN:  env_incl = true;
         case EXECVE_EN:   // Fall through intentional
                           succ = enter_execve(p, q, env_incl);
                           break;
         case FCHDIR_EN:   succ = enter_fchdir(p, q); break;
         case FCHMOD_EN:   succ = enter_fchmod(p, q); break;
         case FORK_EN:     succ = enter_fork(p, q); break;
         case FTRUNC_EN:   succ = enter_ftruncate(p, q); break;
         case KILL_EN:     succ = enter_kill(p, q); break;
         case LINK_EN:     succ = enter_link(p, q); break;
         case MKDIR_EN:    succ = enter_mkdir(p, q); break;
         case MMAP_EN:     succ = enter_mmap(p, q); break;
         case PTRACE_EN:   succ = enter_ptrace(p, q); break;
         case RENAME_EN:   succ = enter_rename(p, q); break;
         case RMDIR_EN:    succ = enter_rmdir(p, q); break;
         case SETGID_EN:   succ = enter_setgid(p, q); break;
         case SETUID_EN:   succ = enter_setuid(p, q); break;
         case SYMLINK_EN:  succ = enter_symlink(p, q); break;
         case TRUNC_EN:    succ = enter_truncate(p, q); break;
         case UNLINK_EN:   succ = enter_unlink(p, q); break;
         case MKNOD_EN:    succ = enter_mknod(p,q); break;
         case FI_MODULE_EN:succ = enter_finit_module(p,q); break;
         case I_MODULE_EN: succ = enter_init_module(p,q); break;
         case SPLICE_EN:   succ = enter_splice(p,q); break;
         case VMSPLICE_EN: succ = enter_vmsplice(p,q); break;
         case TEE_EN:      succ = enter_tee(p,q); break;
         case SOCKET_EN:   succ = enter_socket(p,q); break;
         case ACCEPT_EX:   succ = exitt_saddr(ACCEPT_EX, p, q); break;
         case BIND_EX:     succ = exit_sc(BIND_EX, p, q); break;
         case CHDIR_EX:    succ = exitt_sc(CHDIR_EX, p, q); break;
         case CHMOD_EX:    succ = exit_sc(CHMOD_EX, p, q); break;
         case CLONE_EX:    succ = exitt_ids(CLONE_EX, p, q); break;
         case CLOSE_EX:    succ = exit_sc(CLOSE_EX, p, q); break;
         case CONNECT_EX:  succ = exit_connect(p, q); break;
         case DUP_EX:      succ = exit_dup(DUP_EX, p, q); break;
         case DUP2_EX:     succ = exit_dup(DUP2_EX, p, q); break;
         case EXECVE_EX:   succ = exitt_ids(EXECVE_EX, p, q); break;
         case FCHDIR_EX:   succ = exitt_sc(FCHDIR_EX, p, q); break;
         case FCHMOD_EX:   succ = exit_sc(FCHMOD_EX, p, q); break;
         case FORK_EX:     succ = exitt_ids(FORK_EX, p, q); break;
         case FTRUNC_EX:   succ = exit_sc(FTRUNC_EX, p, q); break;
         case GETPEER_EX:  succ = exitt_saddr(GETPEER_EX, p, q); break;
         case KILL_EX:     succ = exit_sc(KILL_EX, p, q); break;
         case LINK_EX:     succ = exit_sc(LINK_EX, p, q); break;
         case MKDIR_EX:    succ = exit_sc(MKDIR_EX, p, q); break;
         case MMAP_EX:     succ = exit_mmap(p, q); break;
         case MPROTECT_EX: succ = exit_mprotect(p, q); break;
         case OPEN_EX:     succ = exit_open(p, q); break;
         case PIPE_EX:     succ = exit_pipe(PIPE_EX, p, q); break;
         case PTRACE_EX:   succ = exit_sc(PTRACE_EX, p, q); break;
         case READ_EX:     succ = exit_read(p, q); break;
         case RECVFROM_EX: succ = exitt_saddr(RECVFROM_EX, p, q); break;
         case RENAME_EX:   succ = exit_sc(RENAME_EX, p, q); break;
         case RMDIR_EX:    succ = exit_sc(RMDIR_EX, p, q); break;
         case SENDTO_EX:   succ = exit_sendto(p, q); break;
         case SETGID_EX:   succ = exit_sc(SETGID_EX, p, q); break;
         case SETUID_EX:   succ = exit_sc(SETUID_EX, p, q); break;
         case SOCKPAIR_EX: succ = exit_pipe(SOCKPAIR_EX, p, q); break;
         case SYMLINK_EX:  succ = exit_sc(SYMLINK_EX, p, q); break;
         case TRUNC_EX:    succ = exit_sc(TRUNC_EX, p, q); break;
         case UNLINK_EX:   succ = exit_sc(UNLINK_EX, p, q); break;
         case WRITE_EX:    succ = exit_write(p, q); break;
         case I_MODULE_EX: succ = exit_sc(I_MODULE_EX, p, q); break;
         case FI_MODULE_EX:succ = exit_sc(FI_MODULE_EX, p, q); break;
         case MKNOD_EX:    succ = exit_sc(MKNOD_EX, p, q); break;
         case SPLICE_EX:   succ = exit_sc(SPLICE_EX,p,q); break;
         case VMSPLICE_EX: succ = exit_sc(VMSPLICE_EX,p,q); break;
         case TEE_EX:      succ = exit_sc(TEE_EX,p,q); break;
         case SOCKET_EX:   succ = exit_sc(SOCKET_EX,p,q); break;
         default: 
            succ = false;
            break;
         }

         if (succ) 
            if (exit_op) {
               exit_rec++;
               scexit_count[(uint8_t)sc]++;
            }
            else {
               entry_rec++; 
               if (sc != TS_DIFF && sc != TS_KERN && sc != TSMS_EN)
                  sc_count[(uint8_t)sc]++;
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
   buf = (char*)p;
   parse_buffer(p, &p[len], true);
}

int infd;

void
parse_stream() {
   const char *p=buf;
   char *q=buf;
   ssize_t nb=-1000000;
   nr=0;

   // The possible largest record size is about 8K for execve. Use a buffer that
   // is 8 times larger, so data copies (from buffer end to beginning) will be
   // no more than 1/7th of the data that was gainfully processed.
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

void prtUsage(int argc, char* argv[]) {
  cerr << "Usage: " << argv[0] << " [-s] [-#] [-c] {-i myIPaddress}+ [-l logLevel]"
   " {-n networkAddr/netMask}+ [-o] [-pf] [-ps] [-r] [-w width]"
   " [-I <auditFile>] [-P [<printFile>]] [-R <recordFile>]\n"
   "    -c: sort counts by frequency\n"
   "    -l logLevel: specify logging level, defaults to "<< ERRLEVEL << endl <<
   "    -o: record opens in the record file\n"
   "    -pf: print the list of files accessed\n"
   "    -ps: print the list of sockets accessed\n"
   "    -r: record reads and writes in the record file\n"
   "    -s: indicates that sequence numbers are NOT included in capture file\n"
   "    -#: indicates that processor core #s are included in capture file\n"
   "    -w width: format output for display with width columns\n"
   "eAudit records are read from stdin or <auditFile>.\n"
   "They are printed to <printFile> (default: stdout) if -P flag is specified.\n"
   "Information recorded in <recordFile> if -R option is specified.\n"
   "Record file will use gzip compression if <recordFile> ends with .gz.\n";
   exit(1);
}

int width=80;
int logLevel=ERRLEVEL; // WARNLEVEL, ERRLEVEL, etc. Zero means don't complain

static void
parseCmdline(int argc, char* argv[], const char*& infn,
             bool& do_print, const char*& prtfn, const char*& recfn, 
             bool& use_seqnum, bool& use_procid, bool& auditRdWr, bool& logOpen,
             bool& summarizeFiles, bool& summarizeEP, bool& sortByFreq,
             vector<unsigned>*& ipaddrs, vector<unsigned>*& netmasks, 
             vector<unsigned>*& netaddrs) {

   infn=nullptr;
   do_print=false;
   prtfn=nullptr;
   recfn=nullptr;
   use_seqnum = true;
   use_procid = false;
   auditRdWr=true;
   logOpen=false;
   summarizeFiles=false;
   summarizeEP=false;
   sortByFreq=true;
   ipaddrs=nullptr;
   netmasks=nullptr;
   netaddrs=nullptr;

   for (int i=1; i < argc; i++) {
      if (argv[i][0] == '-') {
         switch (argv[i][1]) {
         case 'c': sortByFreq=true; break;

         case 'i': {
            unsigned r1, r2, r3, r4;
            if (++i >= argc ||
                 (sscanf(argv[i], "%d.%d.%d.%d", &r1, &r2, &r3, &r4) < 4))
                prtUsage(argc, argv);
            ipaddrs = new vector<unsigned>;
            ipaddrs->push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            break;
         }

         case 'l':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &logLevel) < 1))
               prtUsage(argc, argv);
            break;

         case 'n': {
            unsigned r1, r2, r3, r4, r5, r6, r7, r8;
            if (++i >= argc ||
                (sscanf(argv[i], "%d.%d.%d.%d/%d.%d.%d.%d", &r1, &r2, &r3, &r4,
                   &r5, &r6, &r7, &r8) < 8))
               prtUsage(argc, argv);
            netaddrs = new vector<unsigned>;
            netmasks = new vector<unsigned>;
            netaddrs->push_back((r1<<24)+(r2<<16)+(r3<<8)+r4);
            netmasks->push_back((r5<<24)+(r6<<16)+(r7<<8)+r8);
            break;
         }

         case 'o': logOpen = true; break;

         case 'p': 
            if (argv[i][2] == 'f') 
               summarizeFiles = true;
            else if (argv[i][2] == 's')
               summarizeEP = true;
            else prtUsage(argc, argv);
            break;

         case 'r': auditRdWr = true; break;

         case 'w':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &width) < 1))
               prtUsage(argc, argv);
            break;

         case 'I':
            if (++i >= argc)
               prtUsage(argc, argv);
            infn = argv[i];
            break;

         case 'P':
            do_print = true;
            if (++i >= argc)
               prtUsage(argc, argv);
            prtfn = argv[i];
            break;            

         case 'R':
            if (++i >= argc)
               prtUsage(argc, argv);
            recfn = argv[i];
            break;

         case '#':
            use_procid = !use_procid;
            break;

         case 's':
            use_seqnum = !use_seqnum;
            break;

         default: prtUsage(argc, argv); break;
         }
      }
   }
}

void
parser_init(const char* infn, const char* prtfn, const char* recfn, 
            bool use_seqnum, bool use_procid, bool auditRdWr, bool logOpen, 
            bool summarizeFiles, 
            bool summarizeEP, bool sortByFreq, const vector<unsigned>* ipaddrs, 
            const vector<unsigned>* netmasks, const vector<unsigned>* netaddrs) {

   init_scname();

   if (infn) {
      if ((infd = open(infn, O_RDONLY)) < 0)
         errexit("Unable to open input file");
   }
   else infd = 0; // By default, input read from stdin

   if (prtfn && *prtfn) {
      print_log = true;
      if (*prtfn != '-') {
         ofp = fopen(prtfn, "w");
         if (!ofp)
            errexit("Unable to open output file");
      }
      else ofp = stdout; // By default, formatted records are printed to stdout
   }
   else ofp = nullptr;

   /* Ignore SIG_INT if not reading from TTY. Also ignore SIGPIPE. It is better
      to wait for the input stream to be closed or a read to return error. */
   if (!isatty(infd))
      signal(SIGINT, SIG_IGN);
   signal(SIGPIPE, SIG_IGN);

   useseqnum = use_seqnum;
   useprocid = use_procid;
}

void
parser_finish() {
   if (ofp) {
      fputc('\n', ofp);
      fflush(ofp);
   }

   fprintf(stderr, "****************************** Summary from Parser "
           "*****************************\n");
   fprintf(stderr, 
      "Syscalls enters=%ld, exits=%ld, exits with errors=%ld\n"
      "Records: time=%ld, sync=%ld, corrupted=%ld, truncated str=%ld, data=%ld\n",
      entry_rec-tsdiff_rec-tsms_rec, exit_rec, exit_errs,
      tsms_rec+tsms_rec1, tsdiff_rec, err_rec, trunc_fn, trunc_data);
   prtSortedCounts(sc_count, scname, 255, "Scall", "Counts of Syscalls", width);
   prtSortedCounts(scexit_count, scname, 255, "Scall", "Syscall exits", width);
   fprintf(stderr, "Out of order records: %ld, average backward slip %g seconds\n", 
           n_out_of_order, t_out_of_order/(1e9*n_out_of_order));
   if (skipped >0 || err_rec > 0)
      fprintf(stderr, "Read %ld bytes, skipped %ld bytes due to errors\n",
              nr, skipped);

   if (tamper_windows > 0) {
      fprintf(stderr, "Tamper window: %g syscalls (%g critical, %g important)\n",
              tamper_count/(double)tamper_windows, 
              tamper_ccount/(double)tamper_windows,
              tamper_icount/(double)tamper_windows);
      fprintf(stderr, "Max tamper window duration was %gms (%gms critical,"
              " %gms important)\n",
              tamper_maxlag/1e6, tamper_maxclag/1e6, tamper_maxilag/1e6);
            tamper_totclag += tamper_thisclag;
            tamper_thisclag = 0;
      fprintf(stderr, "Average tamper window duration was %gms (%gms critical,"
              " %gms important)\n",
              tamper_totlag/(1e6*tamper_windows), 
              tamper_totclag/(1e6*tamper_windows),
              tamper_totilag/(1e6*tamper_windows));
      fprintf(stderr, 
              "Windows: %ld, Events: critical %lu, important %lu, all %lu, "
              "max lag=%gms\n", tamper_windows, tamper_totclag, tamper_totilag, 
              tamper_totlag, max_kernel_ts_clk_kernel_diff/1e6);
      cerr << "Histograms: ";
      tamperlag.print(cerr);
      cerr << "\nCritical: ";
      tamperclag.print(cerr);
      cerr << "\nImportant: ";
      tamperilag.print(cerr);
      cerr << endl;
   }
}

int parseCmdlineAndProcInput(int argc, char* argv[]) {
   bool do_print;
   bool use_seqnum, use_procid, auditRdWr, logOpen, summarizeFiles, summarizeEP;
   bool sortByFreq;
   const char *infn, *prtfn, *recfn;
   vector<unsigned> *ipaddrs, *netmasks, *netaddrs;

   parseCmdline(argc, argv, infn, do_print, prtfn, recfn, use_seqnum, use_procid,
                auditRdWr, logOpen, summarizeFiles, summarizeEP, 
                sortByFreq, ipaddrs, netmasks, netaddrs);
   if (do_print && !prtfn)
      prtfn = strdup("-");
   parser_init(infn, prtfn, recfn, use_seqnum, use_procid, 
               auditRdWr, logOpen, summarizeFiles, summarizeEP, sortByFreq, 
               ipaddrs, netmasks, netaddrs);
   
   parse_stream();
   parser_finish();
   return 0;
}
