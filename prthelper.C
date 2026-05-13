#include <sys/socket.h>
#include <asm/types.h>
#include <sys/un.h>
#include <netdb.h>
#include <linux/netlink.h>
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
#include <signal.h>

#include <vector>
#include "STLutils.h"

#include "eauditk.h"
#include "prthelper.h"

string
countReadable(long count, int w) {
   char ss[21];
   if (count/1000000000>=1) sprintf(ss,"%.*f%s", w, count/1000000000.0, "B");
   else if (count/1000000>=1) sprintf(ss,"%.*f%s", w, count/1000000.0, "M");
   else if (count/1000>=1) sprintf(ss,"%.*f%s", w, count/1000.0, "K");
   else sprintf(ss,"%ld", count);
   return string(ss);
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

long nprt;

void
prttspid(uint64_t ts, int p, uint32_t sn, uint8_t procid, 
         bool useseqnum, bool useprocid, bool longts, FILE *ofp) {
   static uint64_t last_ts;

   static char c[64];
   int j=63;
   static int ts_idx;
   const int pid_idx=47;
   if (!longts)
      ts = ts/1000000;
   else ts = ts/1000;

   /*if (pid == last_tid)
      j = pid_idx;
   else {*/
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
   //}

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
         if (!longts) {
            if (++l == 3)
               c[--j] = '.';
         }
         else if (++l == 6)
            c[--j] = '.';
      }
      c[--j] = '\n';
      nprt++;
      ts_idx = j;
   }
   fputs(&c[ts_idx], ofp);
}

void
prt_open(int at_fd, const char* fn, int fl, int md, int ret, 
         long at_id, long ret_id, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "open(");
   if (at_fd != AT_FDCWD) {
      if (at_id && at_id != at_fd)
         fprintf(ofp, "at=%d [id=%lu], ", at_fd, at_id);
      else fprintf(ofp, "at=%d, ", at_fd);
   }
   fprintf(ofp, "file=\"%s\", flags=%x, mode=%#o) ret=%d",
           fn, fl, md, ret);
   if (ret_id && ret_id != ret) 
      fprintf(ofp, " [id=%lu]", ret_id);
   if(is_tampered) fprintf(ofp," tampered=y");
   
}

void
prt_ret(const char* scnm, long ret, int pid, int tid, int last_pid, int last_tid,
             bool force_ts, FILE* ofp, bool is_tampered) {
   if (force_ts || pid != last_pid || tid != last_tid)
      fprintf(ofp, "%s ret=%ld", scnm, ret);
   else fprintf(ofp, " ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_exitids(const char* scnm, int par_tid, int ret, int uid, int gid, 
            long cgroup, int pid, int tid, int last_pid, int last_tid,
             bool force_ts, FILE* ofp, bool is_tampered) {
   if (force_ts || pid != last_pid || tid != last_tid) {
      fprintf(ofp, "%s ret=%d parent_tid=%d uid=%d gid=%d cgroup=%ld",
              scnm, ret, par_tid, uid, gid, cgroup);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
      

   else {
      fprintf(ofp, " ret=%d parent_tid=%d uid=%d gid=%d cgroup=%ld",
              ret, par_tid, uid, gid, cgroup);
      if(is_tampered) fprintf(ofp," tampered=y");
         
   }
}

void
prt_dup(const char* scnm, long fd, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "%s(fd=%ld) ret=%ld", scnm, fd, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_fchdir(long fd, long id, long ret, FILE* ofp, bool is_tampered) {
   if (id && id != fd) {
      fprintf(ofp, "fchdir(fd=%lu [id=%lu]) ret=%ld", fd, id, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
   else {
      fprintf(ofp, "fchdir(fd=%lu) ret=%ld", fd, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
         
   } 
}

void
prt_fchmod(long fd, long id, long mode, long ret, FILE* ofp, bool is_tampered) {
   if (id && id != fd){
      fprintf(ofp, "fchmod(fd=%lu [id=%lu], mode=%#lo) ret=%ld", fd,id,mode,ret);
      if(is_tampered) fprintf(ofp," tampered=y");
      
   }
   else {
      fprintf(ofp, "fchmod(fd=%lu, mode=%#lo) ret=%ld", fd, mode, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
}

void
prt_read(long fd, long id, long ret, FILE* ofp, bool is_tampered) {
   if (id && id != fd) {
      fprintf(ofp, "read(fd=%lu [id=%lu]) ret=%ld", fd, id, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
      
   else {
      fprintf(ofp, "read(fd=%lu) ret=%ld", fd, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
}

void
prt_write(long fd, long id, long ret, FILE* ofp, bool is_tampered) {
   if (id && id != fd){
      fprintf(ofp, "write(fd=%lu [id=%lu]) ret=%ld", fd, id, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
   else{
      fprintf(ofp, "write(fd=%lu) ret=%ld", fd, ret);
      if(is_tampered) fprintf(ofp," tampered=y");
   }
}

void
prt_close(long fd, long unrep_rd, long unrep_wr, FILE* ofp, bool is_tampered) {
/*
   if (unrep_rd) {
      prt_read(fd, unrep_rd, ofp);
      prt_ts_and_pid();
   }
   if (unrep_wr) {
      prt_write(fd, unrep_wr, ofp);
      prt_ts_and_pid();
   }
*/
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
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_pipe_spair(uint8_t sc, int fd1, int fd2, FILE* ofp, bool is_tampered) {
   fputs(sc==PIPE_EX? "pipe" : "socketpair", ofp);
   fprintf(ofp, "() fd1=%d fd2=%d", fd1, fd2);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
print_saddr(uint8_t *sa, uint64_t len, FILE* ofp) {
   if (len < sizeof(sa_family_t)) {
      // fprintf(ofp, "invalid: ");
      return;
   }

   saddr_t& saddr = *(saddr_t*)sa;
   char s[128], pt[16];

   switch (saddr.sun.sun_family) {
   case AF_LOCAL: {
      struct sockaddr_un& un = saddr.sun;
      fprintf(ofp, "unix:");
      if (len == sizeof(sa_family_t))
         fprintf(ofp, "unnamed");
      else if (un.sun_path[0] == '\0') {
        // These are special endpoints that don't create a file.
        // Don't ignore, thinking it is an (invalid) null string.
        bin2str(ofp, un.sun_path, len-sizeof(sa_family_t));
      }
      else {
         assert_abort(len >= 2);
         char tp = un.sun_path[min(107ul, len-2)];
         un.sun_path[min(107ul, len-2)] = '\0';
         fprintf(ofp, "%s", (char*)un.sun_path);
         un.sun_path[min(107ul, len-2)] = tp;
      }
      break;
   }

   case AF_INET: {
      const struct sockaddr_in& in = saddr.sin;
      unsigned ip = in.sin_addr.s_addr;
      unsigned short port = ntohs(in.sin_port);
      fprintf(ofp, "IP4:%d.%d.%d.%d:%d",
         ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff,
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
                  s, sizeof(s), pt, sizeof(pt),
                  NI_NUMERICHOST|NI_NUMERICSERV);
      fprintf(ofp, "IP6:%s:%s", s, pt);
      break;
   }

   default:
      // fprintf(ofp, "invalid:");
      break;
   }
}

void
prt_saddr(const char* scnm, long fd, long id, long ret, uint8_t *saddr, 
          unsigned slen, FILE* ofp)  {
   if (id && id != fd)
      fprintf(ofp, "%s(fd=%lu [id=%lu]", scnm, fd, id);
   else fprintf(ofp, "%s(fd=%lu", scnm, fd);

   fprintf(ofp, ", endpoint=");
   if (slen > 0)
      print_saddr(saddr, slen, ofp);
   fprintf(ofp, ") ret=%ld", ret);
}

void
prt_saddr(const char* scnm, long fd, long id, long ret, const char* epnm, 
          short family, short port, FILE* ofp)  {
   if (id && id != fd)
      fprintf(ofp, "%s(fd=%lu [id=%lu], endpoint=", scnm, fd, id);
   else fprintf(ofp, "%s(fd=%lu, endpoint=", scnm, fd);
   switch (family) {
   case AF_LOCAL:   fprintf(ofp, "unix:%s", epnm); break;
   case AF_NETLINK: fprintf(ofp, "netlink:%s", epnm); break;
   case AF_INET6:   fprintf(ofp, "IP6:%s:%d", epnm, (int)port); break;
   default:         fprintf(ofp, "invalid:"); break;
   }
   fprintf(ofp, ") ret=%ld", ret);
}

void
prt_saddr(const char* scnm, long fd, long id, long ret, unsigned ip, 
          unsigned short port, FILE* ofp)  {
   if (id && id != fd)
      fprintf(ofp, "%s(fd=%lu [id=%lu], endpoint=", scnm, fd, id);
   else fprintf(ofp, "%s(fd=%lu, endpoint=", scnm, fd);
   fprintf(ofp, "IP4:%d.%d.%d.%d:%d", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff,
              ip>>24, port);
   fprintf(ofp, ") ret=%ld", ret);
}

void
prt_saddr(const char* scnm, long fd, long id, long ret, const char *nm,
          FILE* ofp)  {
   if (id && id != fd)
      fprintf(ofp, "%s(fd=%lu [id=%lu], endpoint=", scnm, fd, id);
   else fprintf(ofp, "%s(fd=%lu, endpoint=", scnm, fd);
   fprintf(ofp, "%s", nm);
   fprintf(ofp, ") ret=%ld", ret);
}

void
prt_connect(long fd,long id, long ret, uint8_t *saddr, unsigned slen,FILE* ofp,
            bool is_tampered) {
   if (id && id != fd)
      fprintf(ofp, "connect(fd=%lu [id=%lu], endpoint=", fd, id);
   else fprintf(ofp, "connect(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen, ofp);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_bind(long fd, uint8_t *saddr, unsigned slen, long ret, FILE* ofp, bool is_tampered)  {
   fprintf(ofp, "bind(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen, ofp);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_sendto(long fd, uint8_t *saddr, unsigned slen, long ret, FILE* ofp, bool is_tampered)  
   {
   fprintf(ofp, "sendto(fd=%lu, endpoint=", fd);
   print_saddr(saddr, slen, ofp);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_truncate(const char* fn, long len, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "truncate(file=\"%s\", len=%ld) ret=%ld", fn, len, ret);
    if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_ftruncate(int fd, long id, long len, long ret, FILE* ofp, bool is_tampered) {
  if (id && id != fd)
    fprintf(ofp, "ftruncate(fd=%d [id=%lu], len=%ld) ret=%ld", fd, id, len, ret);
  fprintf(ofp, "ftruncate(fd=%d, len=%ld) ret=%ld", fd, len, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_mmap(long addr, long len, int prot, int flags, long id, 
             long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, 
      "mmap(addr=%lx, len=%ld, prot=%d, flags=%x, id=%ld) ret=%lx",
         addr, len, prot, flags, id, ret);
   if(is_tampered) fprintf(ofp," tampered=y");      }

void
prt_error_entry(long errcode, long sc, FILE* ofp) {
   if (errcode == ARG_LOOKUP_ERR)
      fprintf(ofp, "argument lookup failed at exit for syscall %ld", sc);
   else fprintf(ofp, "Unknown error code %ld, argument=%ld", errcode, sc);
}

void
prt_mprotect(long addr, long len, long prot, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "mprotect(addr=%lx, len=%ld, prot=%lx) ret=%ld",
           addr, len, prot, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_unlink(long fd, long id, const char* fn, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "unlink(");
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, "at=%lu [id=%lu], ", fd, id);
      else fprintf(ofp, "at=%lu, ", fd);
   }
   fprintf(ofp, "file=\"%s\") ret=%ld", fn, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_mkdir(long fd, long id, const char *fn, long mode, long ret, FILE* ofp,
          bool is_tampered) {
   fprintf(ofp, "mkdir(");
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, "at=%lu [id=%lu], ", fd, id);
      else fprintf(ofp, "at=%lu, ", fd);
   }
   fprintf(ofp, "file=\"%s\", mode=%#lo) ret=%ld", fn, mode, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_mknod(long fd, long id, const char *fn, long mode, long dev, long ret, 
          FILE* ofp, bool is_tampered) {
   fprintf(ofp, "mknod(");
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, "at=%lu [id=%lu], ", fd, id);
      else fprintf(ofp, "at=%lu, ", fd);
   }
   fprintf(ofp, "file=\"%s\", mode=%#lo, dev=%ld) ret=%ld", fn, mode, dev, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_chmod(long fd, long id, const char *fn, long mode, long ret, FILE* ofp,
          bool is_tampered) {
   fprintf(ofp, "chmod(");
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, "at=%lu [id=%lu], ", fd, id);
      else fprintf(ofp, "at=%lu, ", fd);
   }
   fprintf(ofp, "file=\"%s\", mode=%#lo) ret=%ld", fn, mode, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_rmdir(const char* fn, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "rmdir(file=\"%s\") ret=%ld", fn, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_chdir(const char *fn, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "chdir(file=\"%s\") ret=%ld", fn, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_link(long fd1, long id1, long fd2, long id2, const char *s1, const char *s2, 
         long flags, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "link(");
   if (fd1 != AT_FDCWD || fd2 != AT_FDCWD) {
      if ((id1 && id1 != fd1) || (id2 && id2 != fd2))
         fprintf(ofp, "src=\"%s\", at=%lu [id=%lu], dst=\"%s\", at=%lu [id=%lu], "
                 "flags=%ld) ret=%ld", s1, fd1, id1, s2, fd2, id2, flags, ret);
      else fprintf(ofp, "src=\"%s\", at=%lu, dst=\"%s\", at=%lu, flags=%ld) "
                   "ret=%ld", s1, fd1, s2, fd2, flags, ret);
   }
   else fprintf(ofp, "src=\"%s\", dst=\"%s\") ret=%ld", s1, s2, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_rename(long fd1, long id1, long fd2, long id2, const char *s1, 
           const char *s2, long flags, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "rename(");
   if (fd1 != AT_FDCWD || fd2 != AT_FDCWD) {
      if ((id1 && id1 != fd1) || (id2 && id2 != fd2))
        fprintf(ofp, "src=\"%s\", at=%lu [id=%lu], dst=\"%s\", at=%lu [id=%lu]",
              s1, fd1, id1, s2, fd2, id2);
      else fprintf(ofp, "src=\"%s\", at=%lu, dst=\"%s\", at=%lu",
                   s1, fd1, s2, fd2);
   }
   else fprintf(ofp, "src=\"%s\", dst=\"%s\"", s1, s2);
   if (flags != 0) fprintf(ofp, ", flags=%lx", flags);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_symlink(long fd, long id, const char *s1, const char *s2, 
            long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "symlink(src=\"%s\", dst=\"%s\"", s1, s2);
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, ", at=%lu [id=%lu]", fd, id);
      else fprintf(ofp, ", at=%lu", fd);
   }
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void prt_chown(const char *fnm, long user, long grp,
               long fd, long id, long flags, long ret, FILE* ofp,
               bool is_tampered) {
   fprintf(ofp, "chown(file=\"%s\", user=%ld, group=%ld", fnm, user, grp);
   if (fd != AT_FDCWD) {
      if (id && id != fd)
         fprintf(ofp, ", at=%ld [id=%lu]", fd, id);
      else fprintf(ofp, ", at=%ld", fd);
   }
   fprintf(ofp, ", flags=%ld) ret=%ld", flags, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void prt_fchown(long fd, long id, long user, long group, long ret, FILE* ofp,
                bool is_tampered) {
   if (id && id != fd)
      fprintf(ofp, "fchown(fd=%ld [id=%ld], user=%ld, group=%ld) ret=%ld",
              fd, id, user, group, ret);
   else fprintf(ofp, "fchown(fd=%ld, user=%ld, group=%ld) ret=%ld",
                fd, user, group, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void prt_lchown(const char *fnm, long user, long group, long ret, FILE* ofp,
                bool is_tampered) {
  fprintf(ofp, "lchown(file=\"%s\", user=%ld, group=%ld) ret=%ld", fnm, user,
          group, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void prt_mount(const char *dev_name, const char *dir_name,
                      const char *tp, long fl, long ret, FILE* ofp,
                      bool is_tampered) {
  fprintf(ofp, "mount(source=\"%s\", target=\"%s\", ",
   dev_name, dir_name);
  fprintf(ofp, "filesystemtype=\"%s\", mountflags=%ld) ret=%ld",
   tp, fl, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void prt_umount(const char *name, long flags, long ret, FILE* ofp, bool is_tampered) {
  fprintf(ofp, "umount(target=\"%s\", flags=%ld) ret=%ld",
   name, flags, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_kill_no_ret(int pid, int tid, int sig, FILE* ofp, bool is_tampered) {
   if (pid == tid)
      fprintf(ofp, "kill(pid=%d, sig=%d)", pid, sig);
   else if (pid == 0)
      fprintf(ofp, "kill(tid=%d, sig=%d)", tid, sig);
   else fprintf(ofp, "kill(pid=%d, tid=%d, sig=%d)", pid, tid, sig);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_kill(int pid, int tid, int sig, long ret, FILE* ofp, bool is_tampered) {
   if (pid == tid)
      fprintf(ofp, "kill(pid=%d, sig=%d)", pid, sig);
   else if (pid == 0)
      fprintf(ofp, "kill(tid=%d, sig=%d)", tid, sig);
   else fprintf(ofp, "kill(pid=%d, tid=%d, sig=%d)", pid, tid, sig);
   fprintf(ofp, " ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_ptrace(int pid, long req, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "ptrace(req=%lx, pid=%d)", req, pid);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_setuid(int euid, int ruid, int suid, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "setuid(euid=%d", euid);
   if (ruid != INVAL_UID)
      fprintf(ofp, ", ruid=%d", ruid);
   if (suid != INVAL_UID)
      fprintf(ofp, ", suid=%d", suid);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_setgid(int egid, int rgid, int sgid, long ret, FILE* ofp, bool is_tampered)  {
   fprintf(ofp, "setgid(egid=%d", egid);
   if (rgid != INVAL_UID)
      fprintf(ofp, ", rgid=%d", rgid);
   if (sgid != INVAL_UID)
      fprintf(ofp, ", sgid=%d", sgid);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_fork(FILE* ofp, bool is_tampered) {
   fprintf(ofp, "fork()");
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_clone(long flags, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "clone(flags=%lx)", flags);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_clone(long flags, int childpid, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "clone(flags=%lx) ret=%d", flags, childpid);
   if(is_tampered) fprintf(ofp," tampered=y");
}

static void 
prt_argv(const char* nm, const char *const *argv, FILE* ofp) {
   if (!argv)
      fprintf(ofp, ", %s=NULL", nm);
   else
      for (unsigned j=0; argv[j]; j++)
         fprintf(ofp, ", %s[%u]=%s", nm, j, argv[j]);
}

void
prt_execve(long fd, long id, long fl, const char *fn, 
           const char *const *argv, const char *const *envv, 
           FILE* ofp, bool is_tampered, const char* syscall) {
   fprintf(ofp, "%s(file=\"%s\"", syscall, fn);
   if (fd != AT_FDCWD) {
      if (id && id != fd) 
         fprintf(ofp, ", at=%ld [id=%ld]", fd, id);
      else fprintf(ofp, ", at=%ld", fd);
   }
   if (fl != 0)
      fprintf(ofp, ", flags=%lx", fl);
   prt_argv("argv", argv, ofp);
   prt_argv("envp", envv, ofp);
   fprintf(ofp, ")");
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_exit(long flags, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "exit(code=%lx)", flags);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_exitgrp(long flags, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "exitgrp(code=%lx)", flags);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_finit_module(const char * usr_args, long fd, long id, long flags, 
                 long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "finit_module(");
   if (id && id != fd)
      fprintf(ofp, "fd=%lu [id=%ld], ", fd, id);
   else fprintf(ofp, "fd=%lu, ", fd);
   fprintf(ofp, "uargs=\"%s\", flags=%lx", usr_args, flags);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

void
prt_init_module(const char * usr_args, long ret, FILE* ofp, bool is_tampered) {
   fprintf(ofp,"init_module(");
   fprintf(ofp,"uargs=\"%s\"",usr_args);
   fprintf(ofp, ") ret=%ld", ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

/*
void
prt_splice(long off_in, long off_out, long dlen, int fd_in,
           int fd_out, int flags, long ret, FILE* ofp) {
   fprintf(ofp, "splice(");
   fprintf(ofp, "len=%lu, fd_in=%d, fd_out=%d, flags=%d",
                                       dlen, fd_in, fd_out, flags);
   fprintf(ofp, ") ret=%ld", ret);
}
*/

void
prt_vmsplice(int fd, long id, long ret, FILE* ofp, bool is_tampered) {
   if (id && id != fd)
      fprintf(ofp,"vmsplice(fd=%d [id=%lu]) ret=%ld", fd, id, ret);
   else fprintf(ofp,"vmsplice(fd=%d) ret=%ld", fd, ret);
   if(is_tampered) fprintf(ofp," tampered=y");
}

/*
void
prt_tee(long fd_in, long fd_out,long dlen, int flags, long ret, FILE* ofp) {
   fprintf(ofp, "tee(");
   fprintf(ofp, "len=\"%lu\", fd_in=%lu, fd_out=%lu, flags=%d) ret=%ld",
                                       dlen, fd_in, fd_out, flags, ret);
}
*/

void
prt_socket(long family, long type, long protocol, FILE* ofp, bool is_tampered) {
   fprintf(ofp, "socket(");
   fprintf(ofp, "family=%lu, ", family);
   fprintf(ofp, "type=%lu, prot=%lu", type, protocol);
   fprintf(ofp, ")");
   if(is_tampered) fprintf(ofp," tampered=y");
}

