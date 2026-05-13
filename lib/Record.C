#include <fstream>
#include <unistd.h>
#include <sys/wait.h>

#include "Common.h"
#include "Principal.h"
#include "Record.h"

static uint64_t lastts;

Record::Record():
   record_(false),
   popened_(false),
   suspStkTop_(0),
   recFN_(nullptr),
   ofp_(nullptr),
   oopCount_(0),
   sopCount_(0)
{
   suspendRecord_[suspStkTop_] = false;
}

Record::~Record() {
   finishRecording();

   oidrv_.clear();
   sidrv_.clear();

   oiidDefIdx_.clear();
   siidDefIdx_.clear();

   if (recFN_) free(recFN_);
}

static void 
exitError(const char* msg) {
   fprintf(stderr, "%s\n", msg);
   exit(1);
}

static void 
errExit(const char* msg, const char* buf=nullptr, size_t len=0) {
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
setup_popen(const char* cap_file, FILE*& fp, int& fd) {
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

void Record::
startRecording(const char *fn, uint64_t rounding) {
   assert_abort(fn != 0);
   if (oopCount_ != 0 || sopCount_ != 0) {
      errMsg(cout << "Recording must begin before all other operations\n");
      assert_abort(false);
   }

   recFN_ = strdup(fn);
   int ofd; // unused
   if (strcmp(recFN_, "-") == 0) {
      if (isatty(1))
         exitError("Record files cannot be output on terminal");
   }
   else if (index(recFN_, ':')) {
      setup_popen(recFN_, ofp_, ofd);
      popened_ = true;
   }
   else ofp_ = fopen(recFN_, "w");

   if (!ofp_) {
      errMsg(cout << "Unable to open output file\n");
      assert_abort(false);
   }

   if (rounding == 0)
      fprintf(ofp_, "0\n");
   else fprintf(ofp_, "0 %lu\n", rounding);
   record_ = true;
}

void Record::
checkPoint(const char* chkptFN, ostream& os) {
   if (!ofp_) {
      os << "You can only checkpoint while recording data\n";
      return;
   }
   if (chkptFN == 0) {
      os << "Provide valid file name for checkpointing\n";
      return;
   }
   if (strstr(recFN_, ".gz") && 
       strcmp(strstr(recFN_, ".gz"), ".gz") == 0) {
      os << "Checkpointing is not supported on compressed files\n";
      return;
   }

   fflush(ofp_);
   int statusf=0;
   pid_t pid, pid1;

   char s[16] = "cp";
   char *argv[] = {s, recFN_, (char*)chkptFN, 0};
   if ((pid = fork()) == 0) {
      if ((pid = vfork()) == 0) {
         ::execve("/bin/cp", argv, nullptr);
         ::_exit(1);
      }
      else if (pid > 0) {
         pid1 = ::wait(&statusf);
         if (pid != pid1)
            os << "Unexpected child " << pid1 << " returned from wait\n";
         else {
            ofp_ = fopen(chkptFN, "a");
            assert_abort(ofp_ != nullptr);
            finishRecording();
         }
         ::exit(0);
      }
      else os << "checkPoint: cp failed\n";
   }
   else if (pid > 0) {
      pid1 = ::wait(&statusf);
      if (pid != pid1)
         os << "Unexpected child " << pid1 << " returned from wait\n";
   }
   else os << "checkPoint: fork failed\n";
}

void Record::
recAddUser(UId uid, const char* name) {
   fprintf(ofp_, "adduser %s %d\n", name, uid.id());
};

void Record::
recAddGroup(GId gid, const char* name, const vector<UId>& mems) {
   fprintf(ofp_, "addgrp %s %d %lu", name, gid.id(), mems.size());
   for (unsigned i=0; i < mems.size(); i++){
      fprintf(ofp_, " %d", mems[i].id());
   }
   fprintf(ofp_, "\n");
};

void Record::
recCreateStr(const char* s) {
   uint64_t l = strlen(s);
   fprintf(ofp_, "addstr %lu %s\n", l, s);
}

void Record::
recAddLocalPrincipal(UId uid, GId gid, AuthType a1, AuthType a2) {
   fprintf(ofp_, "addLP %d %d %d %d\n", uid.id(), gid.id(), (int)a1, (int)a2);
}

void Record::
recAddRemotePrincipal(unsigned ipaddr, uint16_t port, AuthType a1, AuthType a2) {
   fprintf(ofp_, "addRI %u %d %d %d\n", ipaddr, port, (int)a1, (int)a2);
}

void Record::
recAddRemotePrincipal(StrId cert, uint16_t port, AuthType a1) {
   fprintf(ofp_, "addRC %d %d %d\n", cert.id(), port, (int)a1);
}

#define prtsubj(s) if (s != nullsiid) printf("%lu %lu ", s.id(), idx(s, siidDefIdx_));
#define prtobj(o) if (o != nulloiid) printf("%lu %lu ", o.id(), idx(o, oiidDefIdx_));
void Record::
doRec(const char* opnm, const initializer_list<uint64_t>& args, uint64_t ts,
      SubjInstId inSubj, ObjInstId inObj, SubjInstId outSubj, ObjInstId outObj, SubjInstId inSubj2) {
  //if (ts + 10000 < lastts)
  //   cerr << "Time going backward by over 10ms: from " << lastts << " to " << ts << endl;
  lastts = ts;
  fprintf(ofp_, "%s", opnm);
  for (auto i: args) {
    fprintf(ofp_, " %lu", i);
  }
  if (inSubj != nullsiid)
    fprintf(ofp_, " %lu", idx(inSubj, siidDefIdx_));
  if (inSubj2 != nullsiid)
    fprintf(ofp_, " %lu", idx(inSubj2, siidDefIdx_));
  if (inObj != nulloiid)
    fprintf(ofp_, " %lu", idx(inObj, oiidDefIdx_));
  fprintf(ofp_, " %lu\n", ts);
  recrv(outSubj, siidDefIdx_, sidrv_, sopCount_);
  recrv(outObj,  oiidDefIdx_, oidrv_, oopCount_);

  dbgMsg(cout << opnm << ' '; prtsubj(inSubj); prtsubj(inSubj2); prtobj(inObj); cout << endl);
}

void Record::
recCreateObj(StrId name, PrincipalId owner, Permission perm, 
             NodeType nt, bool force, uint64_t ts, ObjInstId rv) {
   // uint64_t args = 0;
   //args = (args << 4) | (nt & 0xf);
   // args = (args << 1) | override;
   if (!force)
      doRec("CrLO", {name.id(), nt, owner.id(), perm.id()}, 
            ts, nullsiid, nulloiid, nullsiid, rv);
   else
      doRec("CrLO", {name.id(), nt, owner.id(), perm.id(), 1}, 
            ts, nullsiid, nulloiid, nullsiid, rv);
};

/*
void Record::
recCreateEnterpObj(PrincipalId localPrinc, HostId remHost,
           ObjInstId remObj, ObjInstId rv) {
   doRec("CrEO", {localPrinc.id(), remHost.id()}, lastts, nullsubj, nullsubj,
     {remObj}, rv);
};
*/

void Record::
recPreExistingSubj(int mypid, PrincipalId owner, StrId cmd, int parent_pid,
                   uint64_t ts_us, bool isThread, SubjInstId rv) {
   doRec("prS", {(uint64_t)mypid, owner.id(), cmd.id(), (uint64_t)parent_pid, 
                 isThread}, ts_us, nullsiid, nulloiid, rv);
}

void Record::
recClone(SubjInstId parent, int childpid, uint32_t flags, bool isUnit, 
         uint64_t ts, SubjInstId rv) {
   doRec("cln", {(uint64_t)childpid, flags, (uint64_t)isUnit}, ts, parent, 
         nulloiid, rv);
};

void Record::
recExecve(SubjInstId s, StrId name, ObjInstId bin, uint64_t ts) {
   doRec("exve", {name.id()}, ts, s, bin);
};

void Record::
recExit(SubjInstId s, /*int32_t stat,*/ uint64_t ts) {
   doRec("exit", {/*(unsigned)stat*/}, ts, s);
};

/*
void Record::
recWait(SubjInstId waitingSubj, SubjInstId exitingSubj, int32_t exitStatus,
           uint64_t ts, SubjInstId rv) {
   doRec("wait", {(unsigned)exitStatus}, ts, waitingSubj, 
         rv, {}, nullobj, exitingSubj);
};

void Record::
recKill(SubjInstId sender, SubjInstId target, int32_t signal, uint64_t ts, SubjInstId rv) {
   doRec("kill", {(unsigned)signal}, ts, sender, rv, {}, nullobj, target);
};
*/

void Record::
recSetuid(SubjInstId s, PrincipalId npid, uint64_t ts) {
   doRec("suid", {npid.id()}, ts, s, nulloiid);
};

void Record::
recChown(SubjInstId s, ObjInstId o, PrincipalId npid, uint64_t ts) {
   doRec("chwn", {npid.id()}, ts, s, o);
};

void Record::
recChmod(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   doRec("chmd", {p.id()}, ts, s, o);
};

void Record::
recMmap(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   doRec("mmap", {p.id()}, ts, s, o);
};

void Record::
recMprotect(SubjInstId s, ObjInstId o, Permission p, uint64_t ts) {
   doRec("mprot", {p.id()}, ts, s, o);
};

void Record::
recRemove(SubjInstId s, ObjInstId o, uint64_t ts) {
   doRec("rm", {}, ts, s, o);
};

void Record::
recRename(SubjInstId s, ObjInstId oldobj, StrId newname, uint64_t ts,
      StrId oldname) {
   doRec("renm", {newname.id(), oldname.id()}, ts, s, oldobj);
};

void Record::
recCreate(SubjInstId s, NodeType nt, StrId name, Permission perm, uint64_t ts, 
          ObjInstId rv) {
   doRec("creat", {(uint64_t)nt, name.id(), perm.id(), false}, ts,s, nulloiid, 
         nullsiid, rv);
};

void Record::
recOpen(SubjInstId s, ObjInstId o, uint32_t flags, uint64_t ts) {
   doRec("open", {flags}, ts, s, o);
};

void Record::
recRead(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts) {
   doRec("read", {buflen}, ts, s, o);
};

void Record::
recSubjRead(SubjInstId s, SubjInstId ss, uint64_t ts) {
   doRec("rdsub", {}, ts, s, nulloiid, nullsiid, nulloiid, ss);
};

void Record::
recLoadlib(SubjInstId s, ObjInstId o, uint64_t ts) {
   doRec("load", {}, ts, s, o);
};

void Record::
recInject(SubjInstId s, SubjInstId ss, uint64_t ts) {
   doRec("inj", {}, ts, s, nulloiid, nullsiid, nulloiid, ss);
};

void Record::
recWrite(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts) {
   doRec("wrt", {buflen}, ts, s, o);
};

/*
void Record::
recTruncate(SubjInstId s, ObjInstId o, uint32_t len, uint64_t ts,
        OSId rv) {
   doRec("trnc", {len}, ts, s, rv.second, {o}, rv.first);
};
*/

void Record::
recClose(SubjInstId s, ObjInstId o, uint64_t ts) {
   doRec("clos", {}, ts, s, o);
};

void Record::
finishRecording() {
   if (!ofp_)
      return;
   fprintf(ofp_, "end ;\n");
   fflush(ofp_);
   if (popened_)
      pclose(ofp_);
   else fclose(ofp_);
   ofp_=0;
}

