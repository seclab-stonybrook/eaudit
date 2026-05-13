 public:
   // If object with this name exists, don't create new, but return that object.
   ObjInstId createObj(StrId nm, PrincipalId owner, uint64_t ts_us, 
                       bool* flag=0, Permission perm=Permission(0), 
                       NodeType nt=FILE_); // (optional) flag is in-out: if true
                       // on input, then force creation of object even if already
                       // present. On out, indicates if a new object was created.

   pair<ObjInstId, ObjInstId> 
      createRemObjPair(unsigned localIP, uint16_t localPort, unsigned remIP, 
                       uint16_t remPort, uint64_t ts_us, bool *created=nullptr);

   bool addUser(UId uid, const char* name);
   bool addGroup(GId gid, const char* name, const vector<UId>& mems);
   PrincipalId addLocalPrincipal(UId uid, GId pgid,
                                 AuthType a1, AuthType a2=AUTH_NONE);
   PrincipalId addRemotePrincipal(uint32_t ipaddr, uint16_t port,
                                  AuthType a1, AuthType a2=AUTH_NONE);
   PrincipalId addRemotePrincipal(StrId cert, uint16_t port, AuthType a1);

   // To report pre-existing file-like objects (files, directories, devices,...)
   ObjInstId preExistingFile(StrId nm, PrincipalId owner, uint64_t ts_us, 
                        Permission perm, bool *created=0) {
      return createObj(nm, owner, ts_us, created, perm, FILE_);
   }
   // To report pre-existing subjects
   SubjInstId preExistingSubj(PId mypid, PrincipalId owner, StrId cmdline, 
                              PId parent_pid, uint64_t ts_us, bool isThread=0);

   // Events
   SubjInstId clone(SubjInstId parent, PId childpid, uint32_t flags, 
                    uint64_t ts_us, bool isThread=false);
   void execve(SubjInstId s, StrId name, ObjInstId bin, uint64_t ts_us);
   void exit(SubjInstId s, /*int32_t stat,*/ uint64_t ts_us);
   /*void wait(SubjInstId waitingSubj, SubjInstId exitingSubj, 
     int32_t exitStatus, uint64_t ts_us);
   void kill(SubjInstId sender,SubjInstId target, int32_t signal, uint64_t ts);*/
   void setuid(SubjInstId s, PrincipalId npid, uint64_t ts_us);

   ObjInstId create(SubjInstId s, NodeType nt, StrId name, Permission perm, 
                    uint64_t ts_us);

   void open(SubjInstId s, ObjInstId o, uint32_t flags, uint64_t ts_us);

   pair<ObjInstId, ObjInstId> connect(unsigned localIP, uint16_t localPort, 
       unsigned remIP, uint16_t remPort, uint64_t ts_us, bool *created) {
     return createRemObjPair(localIP, localPort, remIP, remPort, ts_us, created);
   }

   pair<ObjInstId, ObjInstId> accept(unsigned localIP, uint16_t localPort, 
       unsigned remIP, uint16_t remPort, uint64_t ts_us, bool *created) {
     return createRemObjPair(localIP, localPort, remIP, remPort, ts_us, created);
   }

   void chown(SubjInstId s, ObjInstId o, PrincipalId npid, uint64_t ts_us);
   void chmod(SubjInstId s, ObjInstId o, Permission p, uint64_t ts_us);

   void remove(SubjInstId s, ObjInstId o, uint64_t ts_us);
   void rename(SubjInstId s, ObjInstId oldobj, StrId newname, uint64_t ts_us,
               StrId oldname=invalidStrId);

   void mprotect(SubjInstId s, ObjInstId o, Permission p, 
                           uint64_t ts_us);
   void mprotectNew(SubjInstId s, uint64_t base, unsigned npages, 
                 Permission p, uint64_t ts_us);
   void mmap(SubjInstId s, ObjInstId o, Permission p, uint64_t ts_us);

   void read(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts_us, 
             bool* useful=0);
   void loadlib(SubjInstId s, ObjInstId o, uint64_t ts_us, 
                bool calledFromExec=false, bool* useful=0);
   void write(SubjInstId s, ObjInstId o, uint32_t buflen, uint64_t ts_us, 
              bool* useful=0);
   void close(SubjInstId s, ObjInstId o, uint64_t ts_us);

   void subjRead(SubjInstId s, SubjInstId s1, uint64_t ts_us, bool* useful=0);
   void inject(SubjInstId s, SubjInstId s1, uint64_t ts_us, bool* useful=0);
