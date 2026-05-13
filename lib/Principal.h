#ifndef PRINCIPAL_H
#define PRINCIPAL_H

/******************************************************************************* 
        Defines users, groups, and principals (remote and local)
******************************************************************************/

#include <stdint.h>
#include <string.h>
#include <vector>

#include "Common.h"

using namespace std;

#define MAX_AUTH_TYPES 2

enum AuthType {
   AUTH_INVALID=0,
   AUTH_NONE,
   AUTH_OS, // Given to auto-started processes such as daemons
   PASSWORD,
   PUBLIC_KEY,
   OTP,
   // possibly other user authentication mechanisms
   CERTIFICATE, // Verified using PK certificate (inside or outside enterprise) 
   VERIFIED_ENTERPRISE, // Verified host within the enterprise
   ENTERPRISE_ENDPOINT, // An IP address or domain name within enterprise
   DNS, // IPaddr obtained by resolving DNS name on the Internet
   DNS_REVDNS, // IPaddr/Domain name combination verified using forward+rev DNS
   TCP, // IP address with bidirectional connectivity 
   IPADDR // Unverified IP address (could be spoofed) --- essentially no auth
};

__attribute__((unused))
static const char* authTypeNm[] = {
   "AUTH_INVALID",
   "AUTH_NONE",
   "AUTH_OS",
   "PASSWORD",
   "PUBLIC_KEY",
   "OTP",
   "CERTIFICATE",
   "VERIFIED_ENTERPRISE",
   "ENTERPRISE_ENDPOINT",
   "DNS",
   "DNS_REVDNS",
   "TCP",
   "IPADDR"
};

const AuthType MAX_USER_AUTH=OTP; // Update if new user auth are added
const AuthType MAX_REMOTE_AUTH=IPADDR; // Update if new remote auth are added

class Permission {
 private:
   uint16_t id_;
 public:
   explicit Permission(uint16_t s=0xffff): id_(s) { };
   uint16_t id() const {return id_; }
   bool operator==(const Permission& t) const { return id_ == t.id_; }
};

static const unsigned OWNER_READ=0400;
static const unsigned OWNER_WRITE=0200;
static const unsigned OWNER_EXEC=0100;
static const unsigned GROUP_READ=0040;
static const unsigned GROUP_WRITE=0020;
static const unsigned GROUP_EXEC=0010;
static const unsigned OTHER_READ=0004;
static const unsigned OTHER_WRITE=0002;
static const unsigned OTHER_EXEC=0001;

static const Permission nullperm(0666); // default (used for network objs etc)
                                        // is read and write for all

enum PrincipalType {
   REMOTE_URL,
   REMOTE_CERT,
   REMOTE_IP,
   ENTERPRISE_HOST,
   ENTERPRISE_USER
};

__attribute__((unused))
static const char* principalTypeNm[] = {
   "REMOTE_URL",
   "REMOTE_CERT",
   "REMOTE_IP",
   "ENTERPRISE_HOST",
   "ENTERPRISE_USER"
};
   

class Principal {
 private:
   uint8_t type_;       // use as a flag in unions involving principals.
   uint8_t atype_;      // Encodes two auth types, must all have the same scope
   union { 
      UId uid_;         // Grouping fields this way, unusual as it may seem,
      uint16_t port_;   // is necessary to get the most compact layout.
   };
   union {
      struct {
         GId gid_;
         HostId hid_;
      } local_;
      uint32_t ipaddr_; // if auth type is not certificate
      StrId url_;       // if auth type is not certificate
      StrId cert_;      // if auth type IS certificate
      HostId hid_;
   };

 public:
   Principal() {atype_ = 0;};

   // Use one of the following options to reduce # of remote principals:
   //  (a) ignore port: specify port as zero
   //  (b) two categories: port=0 (privileged), port=1025 (unprivileged)
   //  (c) few categories: leave a few identified ports (e.g., 80, 53, 22,...)
   //      as they are, replace the rest as in option (b)
   // BUT DON'T LEAVE PORTS AS IS: It makes the notion of principals meaningless.

   Principal(StrId s, uint16_t port, // REMOTE_URL/REMOTE_CERT
             AuthType a1, AuthType a2=AUTH_NONE);
   Principal(uint32_t ipaddr, uint16_t port,  // REMOTE_IPADDR
             AuthType a1, AuthType a2=IPADDR);
   Principal(UId uid, GId pgid, HostId hid, // ENTERPRISE_USER
             AuthType a1, AuthType a2=AUTH_NONE);

   Principal(istream& is);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclass-memaccess"
   Principal(const Principal& o) {memcpy(this, &o, sizeof(o));}
#pragma GCC diagnostic pop

   unsigned numAuth() const { 
      return ((atype_>>4)==AUTH_NONE) ? 0 : ((atype_ & 0xf)==AUTH_NONE ? 1 : 2);
   }
   AuthType auth(int n=0) const {
      return (n < MAX_AUTH_TYPES) ? 
         (AuthType)((n==0) ? (atype_ >> 4) : (atype_ & 0xf)) 
         : AUTH_NONE;
   }
   PrincipalType type() const { return (PrincipalType)type_; };

   UId uid() const { assert_try(type() == ENTERPRISE_USER); return uid_;};
   GId gid() const { assert_try(type() == ENTERPRISE_USER); return local_.gid_; };

   bool isLocal() const { return (type() == ENTERPRISE_USER);};
   bool isRemote() const { return !isLocal();};
   bool isRoot() const { return isLocal() && (uid().id()==0);};
   /*
   bool includes(const Principal* p) const {
      // @@@@ Implemented only for the cases we fully understand
      if (type() == p->type() && 
          (p->auth(1) == auth(1) || p->auth(2) == auth(1))) {
         if (isLocal()) {
            return (p->isRoot())
         }
         else if (isRemote()) {
         }
      }
   */

   Permission getPerm(const Principal* subj, Permission avail) const;

   HostId hostId() const { 
      assert_try(type() == ENTERPRISE_USER || type() == ENTERPRISE_HOST);
      return local_.hid_; 
   };
   uint16_t port() const { assert_try(type() != ENTERPRISE_USER); return port_; }
   StrId cert() const 
     { assert_try(type() == REMOTE_CERT); return cert_; };
   uint32_t ipaddr() const 
     { assert_try(type() == REMOTE_IP); return ipaddr_; }
   StrId url() const 
     { assert_try(type() == REMOTE_URL); return url_; }

   bool operator==(const Principal& p) const {
      return (memcmp(this, &p, sizeof(*this)) == 0);
   }

   void serialize(ostream& os) const;
   void print(ostream& os=cout) const;
}; 

class RealUser { // Captures privileges (set of available logins) of real users.
   const char* name_; // Not to be confused with real/effective userids.
   vector<PrincipalId> login_;

 public:
   RealUser(const char* name, const vector<PrincipalId> &logins):
     name_(name), login_(logins) {};

   const char* name() const { return name_; }
   const PrincipalId login(unsigned n=0) const 
   { return (n < login_.size() ? login_[n] : PrincipalId(0)); }
   bool addLogin(PrincipalId p);
};

static_assert (sizeof(Principal)==8, "fix Principal size");

namespace std {
template <> struct hash<Principal> {
 public :
   size_t operator()(Principal p) const { 
      return fasthash64((void*)&p, sizeof(Principal), sizeof(Principal)); 
   }
};
};
#endif

