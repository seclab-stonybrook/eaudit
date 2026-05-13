#include "Principal.h"

Principal::Principal(uint32_t ipaddr, uint16_t port, AuthType a1, AuthType a2) {
   bzero(this, sizeof(*this));
   type_ = REMOTE_IP;
   assert_abort(a1 > MAX_USER_AUTH);
   atype_ = ((a1<<4) | a2);
   port_ = port;
   ipaddr_ = ipaddr;
}

Principal::Principal(StrId s, uint16_t port, AuthType a1, AuthType a2) {
   assert_abort(a1 != AUTH_NONE);
   bzero(this, sizeof(*this));
   atype_ = ((a1<<4) | a2);
   port_ = port;
   if (a1 == CERTIFICATE) {
      type_ = REMOTE_CERT;
      cert_ = s;
   }
   else {
      type_ = REMOTE_URL;
      url_ = s;
   }
}

Principal::Principal(UId u, GId g, HostId h, AuthType a1, AuthType a2) {
   if (a1==AUTH_NONE) assert_fix(a2==AUTH_NONE, a2=AUTH_NONE);
   bzero(this, sizeof(*this));
   atype_ = ((a1<<4) | a2);
   type_ = ENTERPRISE_USER;
   uid_ = u;
   local_.gid_ = g; 
   local_.hid_ = h;
}

Principal::Principal(istream& is) {
   is.read((char *)this, sizeof(*this));
}

void Principal::serialize(ostream& os) const {
   os.write((char*) this, sizeof(*this));
}

#ifndef RECORD_ONLY
#include "Host.h"

Permission Principal::
getPerm(const Principal* subj, Permission avail) const {
   assert_fix(isLocal() && subj->isLocal(), return Permission());
   if (subj->uid() == uid())
      return Permission((avail.id() | (avail.id() >> 6)) & 0x7);
   else {
      const Host* h = Host::theHostc();
      const vector<UId>& mem = h->members(gid());
      if (find(mem.begin(), mem.end(), subj->uid()) != mem.end())
         return Permission((avail.id() | (avail.id() >> 3)) & 0x7);
   }
   return Permission(avail.id() & 0x7);
}

void Principal::print(ostream& os) const {
   const Host* hi = Host::theHostc();
   os << principalTypeNm[type_] << ": ";
   for (unsigned i=0; i < numAuth(); i++)
      os << authTypeNm[auth(i)] << ' ';

   switch (type_) {
   case ENTERPRISE_USER:
      os << "uid: " << uid().id() << " gid: " << gid().id() << " hid: " 
         << hostId().id() << endl;
     break;
   case ENTERPRISE_HOST:
      os << "port: " << port() << " hid: " << hostId().id() << endl;
     break;
   case REMOTE_IP:
     os << hex << ipaddr() << dec << " port: " << port() << endl;
     break;
   case REMOTE_URL:
     os << hi->str(url()) <<  " port: " << port() << endl;
     break;
   case REMOTE_CERT:
     os << hi->str(cert()) <<  " port: " << port() << endl;
     break;
   default:
     assert_try(false);
   }
}
#endif

bool
RealUser::addLogin(PrincipalId p) {
   for (auto op: login_)
      if (op == p) return false; 
   login_.push_back(p); 
   return true;
}

