#!/usr/bin/python3

#******************************************************************************
#  Copyright 2022-23 R. Sekar and Secure Systems Lab, Stony Brook University
#******************************************************************************
# This file is part of eAudit.
#
# eAudit is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# eAudit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# eAudit. If not, see <https://www.gnu.org/licenses/>.
#****************************************************************************

import sys, platform, os, getopt, ctypes
import random, traceback

import signal
import time
import subprocess
import os
import resource

from bcc import BPF
from time import sleep

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

consumer_rv = 0

#################################################################
# Parse command-line options
#################################################################
def usage():
  lines = ["Usage: " + sys.argv[0] + " <arguments>",
"   -h or --help: print this usage message",
"   -b <bufsz>:  specify (in KB) per-CPU buffer size (range: 0.01 to 8)",
"   -c <capture_file_name>", 
"   -m <prefix> or --machine-friendly <prefix>",
"   -p <number_of_padding_bytes_per_syscall>", 
"   -r <rbufsz>: specify (in MB) ring buffer size (range: 2^n for n in 0..6)",
"   -s: print a summary of system calls made",
"   -S: disable sequence numbers in each record (16-bit)",
"   -v<level>: set verbosity (0: silent, 1: errors, 2: warnings, 3: info)",
"   -u[mor]: report unsuccessful system calls.",
"         m: unsuccessful mprotects", 
"         o: unsuccessful opens (includes accepts, connects, etc.)",
"         r: unsuccessful read/writes",
"   -w <winsz>: set ring-buffer push interval (useful range: 1 to 16)", 
  ];
  eprint("\n".join(lines));
  os._exit(1)

# Set up a few parameters needed by the eBPF probe

WT_THRESH      = (1<<10)
WT_CRITICAL    = (WT_THRESH+1)
WT_IMPORTANT   = (WT_THRESH >> 3)
WT_ENDPOINT    = (WT_THRESH >> 5)
WT_DGRAM       = (WT_THRESH >> 6)
WT_FDTRACK     = (WT_THRESH >> 7)
WT_RDWR        = (WT_THRESH >> 8)
WT_UNIMPORTANT = (WT_THRESH >> 9)
WT_REDUNDANT   = (WT_THRESH >> 10)

REPORT_MMAP_ERRS          = False
REPORT_RDWR_ERRS          = False
REPORT_OPEN_ERRS          = False

perf_fac = 2
padding_size = 0;
ringbuf_size = 8
push_interval = 5
max_tasks = 1<<13
capture_file = ""
verbosity = 2
prt_summary = False
clib = "./ecapd.so"
ebpf_prog = "eauditk.c"
incl_seqnum = True
machine_friendly = ""

try:
    opts, args = getopt.getopt(sys.argv[1:], "b:c:hm:p:r:sSv:u:w:", 
                               ["help"])
    if (len(args) > 0):
       usage();

    for opt, val in opts:
        if opt == "-b":
            perf_fac = float(val);
            if perf_fac < 0.01 or perf_fac > 8:
                eprint("Invalid value for per-cpu buffer size (0.01 to 8)")
                sys.exit(1)
        elif opt == "-c":
            capture_file = val
        elif opt in {"-h", "--help"}:
            usage()
        elif opt in {"-m", "--machine-friendly"}:
            machine_friendly = val
        elif opt == "-p":
            padding_size = int(val);
        elif opt == "-r":
            ringbuf_size = int(val);
            if ringbuf_size not in {1, 2, 4, 8, 16, 32, 64}:
                eprint("Ring buffer size must be one of 1,2,4,8,16,32,64")
                sys.exit(1)
        elif opt == "-s":
            prt_summary = True
        elif opt == "-S":
            incl_seqnum = not incl_seqnum
        elif opt == "-v":
            verbosity = int(val)
        elif opt == "-w":
            push_interval = int(val);
            if push_interval < 1 or push_interval > 16:
                eprint("Invalid value for ring buffer push interval (1..16)")
                sys.exit(1)
        elif opt == "-u":
            if val.find("m") >= 0:
                REPORT_MMAP_ERRS=True
            if val.find("o") >= 0:
                REPORT_OPEN_ERRS=True
            if val.find("r") >= 0:
                REPORT_RDWR_ERRS=True
        else: usage()

except getopt.GetoptError as err:
    eprint(err)
    usage()

except:
    eprint("Invalid options.");
    usage()

if (clib is None):
    eprint("Do not Invoke directly, use ecapd or eauditd shell script")
    sys.exit(1)


#################################################################
# Set up the C++ library to which we output ebpf data
#################################################################
try:
    provider = ctypes.cdll.LoadLibrary(clib)
except OSError:
    eprint("Unable to load the system C library")
    traceback.print_exc(file=sys.stderr)
    sys.exit()

logprinter = provider.logprinter
logprinter.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64]
logprinter.restype = ctypes.c_size_t

init_consumer = provider.init_consumer
init_consumer.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
init_consumer.restype = ctypes.c_size_t

bytes_rcvd = provider.nread
bytes_rcvd.argtypes = None
bytes_rcvd.restype = ctypes.c_size_t

bytes_written = provider.nwritten
bytes_written.argtypes = None
bytes_written.restype = ctypes.c_size_t

do_write = provider.dowrite
do_write.argtypes = None
do_write.restype = ctypes.c_size_t

num_calls = provider.calls
num_calls.argtypes = None
num_calls.restype = ctypes.c_size_t

end_op = provider.end_op
end_op.argtypes = None
end_op.restype = ctypes.c_size_t

#################################################################
# Set up support functions needed before we load the ebpf code
#################################################################
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *args):
        self.kill_now = True

killer = GracefulKiller()

def ppf2(n):
    if (n < 10):
        return "0" + str(n)
    else: return str(n)

def pp(n):
    if n < 1000: return str(n);
    if n < 1000000: return str(n//1000)+"."+ ppf2((n % 1000)//10)+"K"
    if n < 1000000000: return str(n//1000000)+"."+ppf2((n % 1000000)//10000)+"M"
    if n < 1000000000000: 
        return str(n//1000000000)+"."+ppf2((n % 1000000000)//10000000)+"G"

###############################################################################
# Set up all the parameters used by the ebpf probe. Some of them could be set
# at runtime, but for now, it seems good enough to set them up at load time.
###############################################################################
# First, key performance params. Small => low latency, less chance for attacks
# to wipe events before they reach the log file. Large => better performance.
###############################################################################
src = """
#define  TX_THRESH %d
#define  TX_WT_THRESH %d
#define RINGBUF_PAGES %d
#define RINGBUF_PUSH_INTERVAL %d // Fraction of ringbuf outputs that wakeup
#define MAX_TASKS %d
""" % (perf_fac*1024, perf_fac*WT_THRESH, ringbuf_size*256, push_interval, 
       max_tasks);

src += """
#define WT_THRESH      %d
#define WT_CRITICAL    %d
#define WT_IMPORTANT   %d
#define WT_ENDPOINT    %d
#define WT_DGRAM       %d
#define WT_FDTRACK     %d
#define WT_RDWR        %d
#define WT_UNIMPORTANT %d
#define WT_REDUNDANT   %d
#define RSEED          %dul
""" % (WT_THRESH, WT_CRITICAL, WT_IMPORTANT,
       WT_ENDPOINT, WT_DGRAM, WT_FDTRACK, WT_RDWR,
       WT_UNIMPORTANT, WT_REDUNDANT, random.randrange(1<<63))

if padding_size > 0:
    src += "#define PADDING_SIZE " + str(padding_size) + "\n";

src += """
#define PRINTK_LOG_LEVEL         %d
""" % (verbosity)

src += """
#define MY_PID                   %d
""" % (os.getpid())

if incl_seqnum:
    src += "#define  INCL_SEQNUM\n"
if REPORT_MMAP_ERRS:
    src += "#define  REPORT_MMAP_ERRS\n"
if REPORT_RDWR_ERRS:
    src += "#define  REPORT_RDWR_ERRS\n"
if REPORT_OPEN_ERRS:
    src += "#define  REPORT_OPEN_ERRS\n"

src += open(ebpf_prog, "r").read();
b = BPF(text=src);

# First, stop logging.
log_level = b["log_level"];
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);
time.sleep(0.1)

cf = capture_file.encode('utf-8');
pf = "".encode('utf-8');
rf = "".encode('utf-8');
init_consumer(cf, pf, rf);
              
#################################################################
# Load the ebpf program and listen to events
#################################################################
b["events"].open_ring_buffer(logprinter);

# Allow time for any events that were logged before the stop operation above.
# Complain if any bytes have been lost by now.
#
b.ring_buffer_consume()
time.sleep(0.1)
b.ring_buffer_consume()
stats = [v.value for (i, v) in b["mystat"].items()]
if stats[1] != bytes_rcvd() and verbosity >= 2:
    eprint("At start: bytes sent=%d differs from received=%d" % 
          (stats[1], bytes_rcvd()));

# Turn logging back on, proceed to normal operation
#
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (0);

# Can there be performance problems due to BCC's reliance on python? Unlikely
# because the main loop below has just one nontrivial operaton, ring_buffer_poll,
# which is a function in __init__.py in bcc's python source code. That function
# is just a couple of lines, and makes a call to libbcc's C-code that defines
# ring_buffer_poll. The callback from that function is a C-function, so no
# Python overhead in the event handler either.

numpolls=0
try:
    while not killer.kill_now:
        do_write()
        b.ring_buffer_poll()
        numpolls += 1

except KeyboardInterrupt:
    pass

#################################################################
# Done: print stats/summary and exit
#################################################################

# First, set the threshold for logging to very high so that (a) very little
# additinal data will be produced, and (b) whatever is produced is immediately
# transmitted, and won't be left in the ring buffer

log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);

if (verbosity >= 3):
    eprint("Received interrupt, emptying ring buffer");

while True:
    prev_rcvd = bytes_rcvd();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == bytes_rcvd()):
        break;

time.sleep(0.1)

while True:
    prev_rcvd = bytes_rcvd();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == bytes_rcvd()):
        break;

do_write();
end_op()
time.sleep(0.01)

nzcounts = [(i.value, v.value) for (i, v) in b["count"].items() if v.value != 0];
stats = [v.value for (i, v) in b["mystat"].items()]
nsubj = stats[34]

if prt_summary:
    eprint("\nSystem call counts (%d new processes)"
           % nsubj);
    eprint("=======================================");
totsc=0;
for k, v in sorted(nzcounts, key=lambda itm: itm[1]):
    totsc += v;
    if (prt_summary):
        eprint("%3d: %6d" % (k, v));
if (prt_summary):
    eprint("-------------------");

#time.sleep(10)

rb_drops = stats[0];
if (rb_drops > 0) and (verbosity > 0):
    eprint("*** Dropped data *** Ring buffer output failed %d times" % rb_drops)

bytes_sent = stats[1];
bytes_got = bytes_rcvd();
nmsgs = stats[2] and stats[2] or stats[2]+1;
nwakes = stats[3] and stats[3] or stats[3]+1;
if (verbosity > 0):
  if prt_summary:
    eprint("%s Calls, %siB (%s lost), Size: call=%d record=%d\n" % \
      (pp(totsc), pp(bytes_got), pp(bytes_sent-bytes_got), \
       bytes_sent/(totsc+0.01), bytes_sent/nmsgs));
  else:
    eprint("%siB (%s lost), Size: record=%d\n" % \
      (pp(bytes_got), pp(bytes_sent-bytes_got), bytes_sent/nmsgs));

  eprint("%d ringbuf calls with wakeup flag, %d without, %d actual wakes" % 
       (nwakes, nmsgs-nwakes, numpolls));

fn_errs = stats[4];
if (fn_errs > 0) and (verbosity > 2):
    eprint("*** %d file names could not be retrieved ***" % fn_errs)

data_errs = stats[5];
if (data_errs > 0) and (verbosity > 2):
    eprint("*** %d data fields could not be retrieved ***" % data_errs)

argv_errs = stats[6];
if (argv_errs > 0) and (verbosity > 2):
    eprint("*** %d errors while reading argv or envp arrays ***" % argv_errs)

fcntl_errs = stats[7];
if (fcntl_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching fcntl calls ***" % fcntl_errs)

saddr_errs = stats[8];
if (saddr_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching receive socket addr calls ***" % saddr_errs)

pipe_errs = stats[9];
if (pipe_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching pipe calls and returns ***" % pipe_errs)

mmap_errs = stats[10] and (verbosity > 0);
if (mmap_errs > 1):
    eprint("*** %d errors in matching mmap calls and returns ***" % mmap_errs)

str_trunc_err = stats[13];
if (str_trunc_err > 0) and (verbosity >= 2):
    eprint("*** %d strings were too long and were truncated ***" % (str_trunc_err))

data_trunc_err = stats[14];
data_ops = 0;
for i in range(14, 23):
    data_ops += stats[i]
if (data_trunc_err > 0) and (verbosity >= 2):
    if verbosity > 2 or data_trunc_err * 100 > data_ops:
        eprint("*** %d of %d data operations were too long and were truncated ***" 
               % (data_trunc_err, data_ops))

for i in range(16, 23):
    ct = stats[i]
    if (verbosity > 2 and ct > 0  or verbosity == 2 and ct*1000 > data_ops):
        eprint("*** %d data read errors of kind %d ***" % (ct, i))

if machine_friendly:
    eprint("%ssyscalls %d" % (machine_friendly, totsc))
    eprint("%slost %d" % (machine_friendly, bytes_sent-bytes_got))
    eprint("%savgcallsize %d" % (machine_friendly, bytes_sent/totsc))
    eprint("%savgcachesize %d" % (machine_friendly, bytes_sent/nmsgs))
    eprint("%savgp %d" % (machine_friendly, (totsc+nmsgs-1)/nmsgs))
    eprint("%savgw %d" % (machine_friendly, (nmsgs+numpolls-1)/numpolls))
