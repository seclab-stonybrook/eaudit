#ifndef PRT_HELPER_H
#define PRT_HELPER_H

#include <netinet/in.h>
#include <sys/un.h>
#include <linux/netlink.h>

union saddr_t {
   struct sockaddr_un sun;
   struct sockaddr_in sin;
   struct sockaddr_in6 sin6;
   struct sockaddr_nl snl;
};

string countReadable(long count, int w);
inline string countReadable(long c) { return countReadable(c, 1);}

void prtSortedCounts(long count[], const char* const name[], unsigned sz, 
      const char* title="", const char* hdg="", int width=80, FILE* fp=stderr);

void prttspid(uint64_t ts, int pid, uint32_t sn, uint8_t procid, 
              bool useseqnum, bool useprocid, bool longts, FILE *fp);
void prt_ret(const char* scnm, long ret, int pid, int tid, int last_pid, 
             int last_tid, bool force_ts, FILE* ofp, bool is_tampered);
void prt_exitids(const char* scnm, int par_tid, int ret, int uid, int gid, 
                 long cgroup,  int pid, int tid, int last_pid, int last_tid,
                 bool force_ts, FILE* ofp, bool is_tampered);
void prt_error_entry(long errcode, long sc, FILE* ofp);

// Process operations

void prt_clone(long flags, FILE* ofp, bool is_tampered);
void prt_clone(long flags, int childpid, FILE* ofp, bool is_tampered);
void prt_fork(FILE* ofp, bool is_tampered);
void prt_execve(long fd, long id, long fl, const char *fn, 
                /* const char *args, const char *envs, */
                const char *const *argv, const char *const *envv, 
                FILE* ofp, bool is_tampered, const char* syscall="execve");
void prt_exit(long stat, FILE* ofp, bool is_tampered);
void prt_exitgrp(long stat, FILE* ofp, bool is_tampered);
void prt_kill(int pid, int tid, int sig, long ret, FILE* ofp, bool is_tampered);

void prt_kill_no_ret(int pid, int tid, int sig, FILE* ofp, bool is_tampered);
void prt_ptrace(int pid, long req, FILE* ofp, bool is_tampered);
void prt_setuid(int euid, int ruid, int suid, long ret, FILE* ofp, bool is_tampered);
void prt_setgid(int egid, int rgid, int sgid, long ret, FILE* ofp, bool is_tampered);

// Network operations and IPC

void print_saddr(uint8_t *sa, uint64_t len, FILE* ofp);
void prt_saddr(const char* scnm, long fd, long id, long ret, uint8_t *saddr, 
               unsigned slen, FILE* ofp);
void prt_saddr(const char* scnm, long fd, long id, long ret, const char* epnm, 
               short family, short port, FILE* ofp);
void prt_saddr(const char* scnm, long fd, long id, long ret, unsigned ipaddr, 
               unsigned short port, FILE* ofp);
void prt_saddr(const char* scnm, long fd, long id, long ret, const char* epnm, 
               FILE* ofp);
void prt_bind(long fd, uint8_t *saddr, unsigned slen, long ret, FILE* ofp, bool is_tampered);
void prt_connect(long fd, long id, long ret, uint8_t *saddr, 
                 unsigned slen, FILE* ofp, bool is_tampered);
void prt_sendto(long fd, uint8_t *saddr, unsigned slen, long ret, FILE* ofp, bool is_tampered);
void prt_socket(long family, long type, long protocol, FILE* ofp, bool is_tampered);
void prt_pipe_spair(uint8_t sc, int fd1, int fd2, FILE* ofp, bool is_tampered);
void prt_dup(const char* scnm, long fd, long ret, FILE* ofp, bool is_tampered);

// open, close, read, write, etc.

void prt_open(int at_fd, const char* fn, int fl, int md, int ret, 
              long at_id, long ret_id, FILE* ofp, bool is_tampered);
void prt_close(long fd, long unrep_rd, long unrep_wr, FILE* ofp, bool is_tampered);
void prt_truncate(const char* fn, long len, long ret, FILE* ofp, bool is_tampered);
void prt_ftruncate(int fd, long id, long len, long ret, FILE* ofp, bool is_tampered);
void prt_mkdir(long fd, long id, const char *fn, long mode, long ret,FILE* ofp, bool is_tampered);
void prt_mknod(long fd, long id, const char *fn, long mode, long dev, 
               long ret, FILE* ofp, bool is_tampered);
void prt_read(long fd, long id, long ret, FILE* ofp, bool is_tampered);
void prt_write(long fd, long id, long ret, FILE* ofp, bool is_tampered);
void prt_vmsplice(int fd, long id, long ret, FILE* ofp, bool is_tampered);
void prt_mmap(long addr, long len, int prot, int flags, long id, 
              long ret, FILE* ofp, bool is_tampered);
void prt_mprotect(long addr, long len, long prot, long ret, FILE* ofp, bool is_tampered);

// link, rename, remove, etc.

void prt_link(long fd1, long id1, long fd2, long id2, 
              const char *s1, const char *s2, long flags, long ret, FILE* ofp, bool is_tampered);
void prt_symlink(long fd, long id, const char *s1, const char *s2, long ret, 
                 FILE* ofp, bool is_tampered);
void prt_rename(long fd1, long id1, long fd2, long id2, const char *s1, 
                const char *s2, long flags, long ret, FILE* ofp, bool is_tampered);
void prt_unlink(long fd, long id, const char* fn, long ret, FILE* ofp, bool is_tampered);
void prt_rmdir(const char* fn, long ret, FILE* ofp, bool is_tampered);

// chdir, chmode, etc.

void prt_chdir(const char *fn, long ret, FILE* ofp, bool is_tampered);
void prt_fchdir(long fd, long id, long ret, FILE* ofp, bool is_tampered);
void prt_chmod(long fd, long id, const char *fn, long mode, long ret,FILE* ofp, bool is_tampered);
void prt_fchmod(long fd, long id, long mode, long ret, FILE* ofp, bool is_tampered);
void prt_chown(const char *fnm, long user, long grp,
               long fd, long id, long flags, long ret, FILE* ofp, bool is_tampered);
void prt_fchown(long fd, long id, long user, long group, long ret, FILE* ofp, bool is_tampered);
void prt_lchown(const char *fnm, long user, long group, long ret, FILE* ofp, bool is_tampered);

// other administrative operations

void prt_init_module(const char * usr_args, long ret, FILE* ofp, bool is_tampered);
void prt_finit_module(const char * usr_args, long fd, long id, long flags, 
                      long ret, FILE* ofp, bool is_tampered);
void prt_mount(const char *dev_name, const char *dir_name,
                      const char *tp, long fl, long ret, FILE* ofp, bool is_tampered);
void prt_umount(const char *name, long flags, long ret, FILE* ofp, bool is_tampered);

//void prt_splice(long off_in, long off_out, long dlen, int fd_in,
//           int fd_out, int flags, long ret, FILE* ofp, bool is_tampered);
//void prt_tee(long fd_in, long fd_out,long dlen, int flags,long ret,FILE* ofp, bool is_tampered);

#endif
