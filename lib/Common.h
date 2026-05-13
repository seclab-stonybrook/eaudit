#ifndef COMMON_H
#define COMMON_H

#include "STLutils.h"
#include "FastHash.h"
#include "Id.h"

using namespace std;

class Principal;
class Host;
class Subject;
class GraphOutput;
class NodeId;
typedef NodeId EdgeId;

enum NodeType {FILE_, MEM, PIPE, INTRAHOST_CONN, INET_SRC, INET_SINK, INET,
               ENTERP_SRC, ENTERP_SINK, ENTERP, TTY_SRC, TTY_SINK, 
               DEV_SRC, DEV_SINK, PROC, LWPROC, NT_ANY};
__attribute__((unused))
static const char*  nodeTypeNm[] = { 
   "FILE", "MEM", "PIPE", "INTRAHOST_CONN", "INET_SRC", "INET_SINK", "INET",
   "ENTERP_SRC", "ENTERP_SINK", "ENTERP", "TTY_SRC", "TTY_SINK", 
   "DEVICE_SRC", "DEVICE_SINK", "PROCESS", "LT_WGT_PROC", "NT_ANY", "INVALID"};

__attribute__((unused))
static const char*  nodeTypeDoc[] = { 
   "Node type corresponding to files",
   "Node type corresponding to memory objects",
   "Node type corresponding to pipes",
   "Node type corresponding to intrahost connections",
   "Node type corresponding to the receiving side of an internet connection",
   "Node type corresponding to the transmitting side of an internet connection",
   "Node type corresponding to bidirectional internet connection",
   "Node type corresponding to the receive side of an intra-enterprise connection",
   "Node type corresponding to the send side of an intra-enterprise connection",
   "Node type corresponding to bidirectional enterprise connection",
   "Node type corresponding to the input side of a tty",
   "Node type corresponding to the output side of a tty",
   "Node type corresponding to an input device",
   "Node type corresponding to an output device",
   "Node type corresponding to a process",
   "Node type corresponding to a thread",
   "Node type corresponding to an undetermined type"
};


// Simplified resource type: leave out file, mem, and direction (src or sink).
// Up to 16 types, so can explicitly specify common device types (eg camera).
enum ResType {PIPE_R, INTRAHOST_R, ENTERP_R, INET_R, TTY_R, DEV_R};
__attribute__((unused))
static const char* resTypeNm[] = {
   "PIPE", "INTRAHOST_CONN", "ENTERP", "INET", "TTY", "DEV", "INVALID"};

inline NodeType nodeType(ResType t, bool isFile, bool isMem, 
                         bool isSink, bool isSrc) {
   if (isFile) return FILE_;
   else if (isMem) return MEM;
   else switch(t) {
      case PIPE_R: return PIPE;
      case INTRAHOST_R: return INTRAHOST_CONN;
      case INET_R: return isSink? (isSrc? INET : INET_SINK) : INET_SRC; 
      case ENTERP_R: return isSink? (isSrc? ENTERP:ENTERP_SINK) : ENTERP_SRC; 
      case TTY_R: return isSink? TTY_SINK : TTY_SRC; 
      case DEV_R: return isSink? DEV_SINK : DEV_SRC; 
      default: assert_fix(false, return MEM);
      }
};

#endif
