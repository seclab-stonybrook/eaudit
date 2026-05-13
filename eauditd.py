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
import threading

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
"   -b <bufsz>: max cache size (range: 0.01 to 12KB)",
"   -c s<n>: set the task/argument cache size (1<<n).",
"       Use this option multiple times to specify multiple parameters.",
"       s<int>: task/argument cache size exponent",
"   -C: use percpu message caches", 
"   -A <int>: Use idle cache flushing algorithm given by <int>",
"          0: A0 (no flushing), 1: A1 (community flushing),",
"          2: A2 (daemon flushing), 3: A3 (hybrid A1+A2) ",
"   -H: enable tamper detection (UMAC3 signing of records)",
"   -i: use file descriptors instead of ids.",
"   -m <prefix> or --machine-friendly <prefix>: machine-friendly output format ",
"       where <prefix> is added to parameter names in output", 
"   -p: add a 8-bit processor id to each record",
"   -r <rbufsz>: specify (in MB) ring buffer size (range: 2^n for n in 0..6)",
"   -s: print a summary of system calls made",
"   -t <time>: max time messages can be cached (range 1K to 16M nanoseconds)",
"   -u[mor]: report unsuccessful system calls.",
"         m: unsuccessful mprotects", 
"         o: unsuccessful opens (includes accepts, connects, etc.)",
"         r: unsuccessful read/writes",
"   -v<level>: set verbosity 0: silent 1: error 2: warning 3: info 4+: debug",
"   -w <winsz>: set ring-buffer push interval (useful range: 1 to 16)", 
"******* Options following a \"--\" are passed to the user level agent *******",
  ];
  eprint("\n".join(lines));
  os._exit(1)

# Set up a few parameters needed by the eBPF probe

# Global options on the use of sequence numbers, caches, etc.
#-------------------------------------------------------------------------------
long_seqnum = False     # True: use 32-bit seq#, else 16-bit sequence #s.
incl_procid = False     # Whether to include a 1-bit CPU # in syscall records
percpu_cache = False    # False: use PERCPU_MAPS for caches, else use normal maps.
max_cache_time = 1<<20  # Force clearing of msg cache after this much time, even
# if it's below size/weight threshold. It is meaningful only if !percpu_cache. 

# Performance-related parameters
#-------------------------------------------------------------------------------
# perf_fac sets the (initial) size (in KB) and weight threshold (approximate
# unit: number of execve calls in the buffer) for the per-CPU cache, i.e., the
# size/weight of cache before it is queued on ring buffer. Additionally, if the
# weight threshold is crossed, ring buffer call will have the wakeup flag set.
# Default perf_fac setting is in the range of p=100 --- somewhat larger for some
# applications, and possibly lower for others. This is because perf_fac is in
# KB, while p is set in number of syscalls.

perf_fac       = 2  # Similar to p parameter.
ringbuf_size   = 64 # in MB
push_interval  = 5  # w parameter value
flush_algo     = 2  # Default to A2 (daemon flushing) when -A is omitted.
tamper_detect  = False
# True: read/writes report a unique id for each file; False: report fd argument.
#-------------------------------------------------------------------------------
ID_NOT_FD                 = True

# @@@@ These masks need to be inferred automatically, based on network config.
# The default values below are likely meaningless. (Used in id generation to
# determine if an IP address is local to an enterprise or remote. This affects
# how frequently we generate a new id for the same network endpoint.)
IP4NETMASK1=0
IP4NETMASK2=0
IP4NETMASK3=0
IP4NETADDR1=1
IP4NETADDR2=1
IP4NETADDR3=1
NS_TO_LOCAL_EP_EPOCH   = 36 # about 1.15 minutes
NS_TO_FOREIGN_EP_EPOCH = 40 # about 18.3 minutes

# Weights of different system call groups. 
#-------------------------------------------------------------------------------
WT_THRESH      = (1<<10)
WT_CRITICAL    = (WT_THRESH+1)
WT_IMPORTANT   = (WT_THRESH >> 1)
WT_ENDPOINT    = (WT_THRESH >> 5)
WT_DGRAM       = (WT_THRESH >> 6)
WT_FDTRACK     = (WT_THRESH >> 7)
WT_RDWR        = (WT_THRESH >> 8)
WT_UNIMPORTANT = (WT_THRESH >> 9)
WT_REDUNDANT   = (WT_THRESH >> 10)

# The following are used to set the sizes of various caches. Should tune further
# after some deployment experience.
#-------------------------------------------------------------------------------
max_tasks = 1<<13;
# Other key parameters that don't need further documentation.
#-------------------------------------------------------------------------------
machine_friendly = ""

# Some parameters useful for debugging and/or to get more info
#-------------------------------------------------------------------------------
verbosity = 2
prt_summary = False
REPORT_MMAP_ERRS          = False
REPORT_RDWR_ERRS          = False
REPORT_OPEN_ERRS          = False

# Parameters for signing key generation and the circular key ring.
#-------------------------------------------------------------------------------
SIGNING_KEY_SIZE = 16
SIGNING_KEY_BATCH_SIZE = 131072
SIGNING_KEY_RING_SIZE = 2 * SIGNING_KEY_BATCH_SIZE
SIGNING_KEY_HALF_BATCH = SIGNING_KEY_BATCH_SIZE // 2
clib = "./ecapd.so"
ebpf_prog = "eauditk.c"

try:
    opts, user_args = getopt.getopt(sys.argv[1:], "b:CA:iHhl:m:pr:st:u:v:w:c:I:",
                               ["help"])

    for opt, val in opts:
        if opt == "-b":
            perf_fac = float(val);
            if perf_fac < 0.01 or perf_fac > 12:
                eprint("Invalid value for per-cpu buffer size (0.01 to 12)")
                sys.exit(1)
        elif opt == "-c":
            if val.find("s") >= 0:
                exp = int(val[val.find("s")+1:])
                max_tasks = 1<<exp
            else:
                eprint("Invalid cache size selector")
                usage()
        elif opt == "-C":
            percpu_cache = not percpu_cache;
        elif opt == "-A":
                flush_algo = int(val);
                if (flush_algo < 0 or flush_algo > 3):
                    eprint("Invalid cache flushing option");
        elif opt in {"-h", "--help"}:
            usage()
        elif opt == "-H":
            tamper_detect = True
        elif opt == "-i":
            ID_NOT_FD=False
        elif opt == "-l":
            clib = val
        elif opt in {"-m", "--machine-friendly"}:
            machine_friendly = val
        elif opt == "-p":
            incl_procid = not incl_procid
        elif opt == "-r":
            ringbuf_size = int(val);
            if ringbuf_size not in {1,2,4,8,16,32,64,96,128,160,192,224,256,1024}:
                eprint("Ring buffer size should be 1,2,4,8,16, or 32n for n<=8")
                sys.exit(1)
        elif opt == "-s":
            prt_summary = True
        elif opt == "-t":
            max_cache_time = int(val)
            if max_cache_time < 1000:
                eprint("maximum message cache time must be over 1000")
                max_cache_time = 1000;
            if max_cache_time > (1 << 24):
                eprint("maximum message cache time must be under 16M")
                max_cache_time = 1 << 24;
        elif opt == "-u":
            if val.find("m") >= 0:
                REPORT_MMAP_ERRS=True
            if val.find("o") >= 0:
                REPORT_OPEN_ERRS=True
            if val.find("r") >= 0:
                REPORT_RDWR_ERRS=True                
        elif opt == "-v":
            verbosity = int(val)
        elif opt == "-w":
            push_interval = int(val);
            if push_interval < 1 or push_interval > 16:
                eprint("Invalid value for ring buffer push interval (1..16)")
                sys.exit(1)
        else: usage()

except getopt.GetoptError as err:
    eprint(err)
    usage()

except:
    eprint("Invalid options.");
    usage()

if percpu_cache and tamper_detect:
    eprint("Ignoring -H: tamper detection is disabled with -C per-CPU caches")
    tamper_detect = False

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
logprinter.restype = ctypes.c_long

init_consumer = provider.init_consumer
init_consumer.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
init_consumer.restype = ctypes.c_long

nread = provider.nread
nread.argtypes = None
nread.restype = ctypes.c_long

nwritten = provider.nwritten
nwritten.argtypes = None
nwritten.restype = ctypes.c_long

do_write = provider.dowrite
do_write.argtypes = None
do_write.restype = ctypes.c_long

ncalls = provider.calls
ncalls.argtypes = None
ncalls.restype = ctypes.c_long

end_op = provider.end_op
end_op.argtypes = None
end_op.restype = ctypes.c_long

#################################################################
# Set up support functions needed before we load the ebpf code
#################################################################
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        signal.signal(signal.SIGHUP, self.exit_gracefully)

    def exit_gracefully(self, *args):
        self.kill_now = True

    def ignore_sig(self, *args):
        pass

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
""" % (perf_fac*1024, WT_THRESH, ringbuf_size*256, push_interval,
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

src += """
#define MAXCACHETIME             %dul
#define PRINTK_LOG_LEVEL         %d
""" % (max_cache_time, verbosity)

src += """
#define EAUDIT_PID               %d
#define NETMASK1                 %x
#define NETMASK2                 %x
#define NETMASK3                 %x
#define NETADDR1                 %x
#define NETADDR2                 %x
#define NETADDR3                 %x
#define NS_TO_LOCAL_EP_EPOCH     %d
#define NS_TO_FOREIGN_EP_EPOCH   %d
""" % (os.getpid(), 
       IP4NETMASK1, IP4NETMASK2, IP4NETMASK3, 
       IP4NETADDR1, IP4NETADDR2, IP4NETADDR3,
       NS_TO_LOCAL_EP_EPOCH, NS_TO_FOREIGN_EP_EPOCH)

if ID_NOT_FD:
    src += "#define ID_NOT_FD\n" 

src += "#define NUMCPU " + str(os.cpu_count()) + "\n";
if percpu_cache:
    src += "#define  PERCPU_CACHE\n"
else:
    if (flush_algo == 3):
        src += "#define USE_FLUSH_ALGO_A1\n"
        src += "#define USE_FLUSH_ALGO_A2\n"
    else:
        src += "#define USE_FLUSH_ALGO_A" + str(flush_algo) + "\n"

if tamper_detect:
    long_seqnum = True
    src += "#define TAMPER_DETECT\n"
    src += "#define UMAC3\n"

if not long_seqnum:
    src += "#define  SHORT_SEQNUM\n"
if incl_procid:
    src += "#define  INCL_PROCID\n"

if REPORT_MMAP_ERRS:
    src += "#define  REPORT_MMAP_ERRS\n"
if REPORT_RDWR_ERRS:
    src += "#define  REPORT_RDWR_ERRS\n"
if REPORT_OPEN_ERRS:
    src += "#define  REPORT_OPEN_ERRS\n"

src += open(ebpf_prog, "r").read();



b = BPF(text=src);
#b = BPF(text=src, debug=0x1);

# First, stop logging.
log_level = b["log_level"];
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);

# Set up tail calls file descriptors for logging all argv and envp of execve.
#-------------------------------------------------------------------------------
# Keep these slots continuous and aligned with the TAILCALL_* macros in eauditk.c.
TAILCALL_ADD_ARGV = 0
TAILCALL_ADD_ENVP = 1
TAILCALL_UMAC3 = 2
TAILCALL_SIGN_RECORD = 3

fd_add_argv = b.load_func("add_string_tail_argv", BPF.TRACEPOINT)
fd_add_envp = b.load_func("add_string_tail_envp", BPF.TRACEPOINT)
prog_array = b.get_table("tailcall")
prog_array[ctypes.c_int(TAILCALL_ADD_ARGV)] = ctypes.c_int(fd_add_argv.fd)
prog_array[ctypes.c_int(TAILCALL_ADD_ENVP)] = ctypes.c_int(fd_add_envp.fd)

if tamper_detect:
    fd_umac3 = b.load_func("tailcall_umac3", BPF.TRACEPOINT)
    fd_sign_record = b.load_func("tailcall_sign_record", BPF.TRACEPOINT)
    prog_array[ctypes.c_int(TAILCALL_UMAC3)] = ctypes.c_int(fd_umac3.fd)
    prog_array[ctypes.c_int(TAILCALL_SIGN_RECORD)] = ctypes.c_int(
        fd_sign_record.fd)

    # libkeygen.so mirrors the kernel-side key schedule in userspace so the
    # parser and the daemon can derive the same signing material.
    keygen_lib = ctypes.CDLL("./libkeygen.so")

    # ctypes signatures for the helpers that load seeds and expand batches.
    keygen_lib.generate_signing_keys_and_load.argtypes = [ctypes.c_char_p, ctypes.c_int]
    keygen_lib.generate_signing_keys_and_load.restype = ctypes.c_int
    keygen_lib.load_signing_key_seed.argtypes = [ctypes.c_char_p, ctypes.c_int]
    keygen_lib.load_signing_key_seed.restype = ctypes.c_int
    # Per-CPU maps used to stage the current batch, the next batch seed, and
    # the ring-window bookkeeping that tells the daemon which half is live.
    signing_keys_lo_map = b["signing_keys_lo"]
    map_fd_lo = signing_keys_lo_map.get_fd()
    signing_keys_hi_map = b["signing_keys_hi"]
    map_fd_hi = signing_keys_hi_map.get_fd()
    next_seed_map = b["next_batch_seed"]
    map_fd_next_seed = next_seed_map.get_fd()
    initial_seed_map = b["initial_batch_seed"]
    map_fd_initial_seed = initial_seed_map.get_fd()
    key_window_start_map = b["signing_key_window_start"]
    generated_until_map = b["signing_key_generated_until"]

if tamper_detect:
    # Update the lower half of the key ring before logging starts.
    initial_batch_seed_bytes = os.urandom(SIGNING_KEY_SIZE)
    key_buf = ctypes.create_string_buffer(initial_batch_seed_bytes)
    ret = keygen_lib.load_signing_key_seed(key_buf, map_fd_initial_seed)
    if ret != 0:
        eprint("Failed to load initial signing key seed into BPF map "
               "(ret=%d)" % ret)
        sys.exit(1)
    ret = keygen_lib.generate_signing_keys_and_load(key_buf, map_fd_lo)
    if ret != 0:
        eprint("Failed to load initial signing key batch into lower "
               "key-ring map (ret=%d)" % ret)
        sys.exit(1)

    # Preload the next keys so the kernel can embed it at the sync point and
    # the parser can regenerate the upper half of the ring in lockstep.
    next_batch_seed_bytes = os.urandom(SIGNING_KEY_SIZE)
    key_buf = ctypes.create_string_buffer(next_batch_seed_bytes)
    ret = keygen_lib.load_signing_key_seed(key_buf, map_fd_next_seed)
    if ret != 0:
        eprint("Failed to load next signing key seed into BPF map "
               "(ret=%d)" % ret)
        sys.exit(1)
    ret = keygen_lib.generate_signing_keys_and_load(key_buf, map_fd_hi)
    if ret != 0:
        eprint("Failed to load next signing key batch into upper key-ring "
               "map (ret=%d)" % ret)
        sys.exit(1)

    # The initial generation window covers the full ring: [0, 2*batch_size).
    gen_end = SIGNING_KEY_RING_SIZE
    key_window_start_map[ctypes.c_int(0)] = (ctypes.c_ulonglong * 1)(0)
    generated_until_map[ctypes.c_int(0)] = (ctypes.c_ulonglong * 1)(gen_end)

time.sleep(2)

user_args.insert(0, clib)
if (not percpu_cache) and flush_algo != 1:                                                             
    user_args.insert(1, str(max_cache_time)) 
init_args = [x.encode('utf-8') for x in user_args];
nargs = len(init_args)
init_args_c = (ctypes.c_char_p * nargs)(*init_args)
init_consumer(ctypes.c_int(nargs), init_args_c)

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
bytes_sent = stats[1]
if bytes_sent != nread() and verbosity >= 2:
    eprint("At start: bytes sent=%d differs from received=%d" % 
          (bytes_sent, nread()));

# Turn logging back on, proceed to normal operation
#
ierrcount = b["errcount"].values()
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (0);

stats = [v.value for (i, v) in b["mystat"].items()]
unexp_lkp_fail = stats[50]

# Can there be performance problems due to BCC's reliance on python? Unlikely
# since the main loop below has just one nontrivial operation, ring_buffer_poll,
# which is a function in __init__.py in bcc's python source code. That function
# is just a couple of lines, and makes a call to libbcc's C-code that defines
# ring_buffer_poll. The callback from that function is a C-function, so no
# Python overhead in the event handler either.

# The following thresholds are guesses. We should find the right values through
# extensive experimentation.

wakes_rcvd=0
bmsgs_rcvd = b["msgs_rcvd"]

# Dedicated signing-key refill thread: this keeps key expansion off the hot
# ring-buffer path so record delivery stays responsive while tamper detection
# is enabled.
key_refill_stop = threading.Event()

def signing_key_refill_thread_fn():
    global gen_end
    refilled_key_batches = 0
    while not key_refill_stop.is_set():
        try:
            sig = b["key_refill_request"][ctypes.c_int(0)].value
            if sig in [1, 2]:
                # Generate a fresh seed for the next batch; each half-ring
                # expansion begins from its own cryptographically random seed.
                next_batch_seed_bytes = os.urandom(SIGNING_KEY_SIZE)
                key_buf = ctypes.create_string_buffer(next_batch_seed_bytes)
                # Publish the seed for the kernel-side embed path.
                ret = keygen_lib.load_signing_key_seed(key_buf, map_fd_next_seed)
                # signal=2 fills the upper half of the ring; signal=1 fills
                # the lower half.
                if sig == 2:
                    ret = keygen_lib.generate_signing_keys_and_load(key_buf, map_fd_hi)
                else:
                    ret = keygen_lib.generate_signing_keys_and_load(key_buf, map_fd_lo)
                # Advance the parser-visible upper bound after appending a new
                # batch to the ring.
                gen_end += SIGNING_KEY_BATCH_SIZE
                generated_until_map[ctypes.c_int(0)] = (ctypes.c_ulonglong * 1)(gen_end)
                b["key_refill_request"][ctypes.c_int(0)] = ctypes.c_int(0)
                refilled_key_batches += 1
            else:
                time.sleep(0.001)  # Sleep briefly when idle to avoid busy-spin.
        except Exception:
            break
    if verbosity >= 2:
        eprint("Signing key refill thread: generated %d batches" % refilled_key_batches)

if tamper_detect:
    key_refill_thread = threading.Thread(target=signing_key_refill_thread_fn, daemon=True)
    key_refill_thread.start()

try:
    while not killer.kill_now:
        b.ring_buffer_poll()
        msgs_rcvd = do_write()
        bmsgs_rcvd[ctypes.c_int(0)] = (ctypes.c_long*1) (int(msgs_rcvd))
        wakes_rcvd += 1

except KeyboardInterrupt:
    pass

if tamper_detect:
    key_refill_stop.set()
    key_refill_thread.join(timeout=2)

#################################################################
# Done: print stats/summary and exit
#################################################################

# In order to cleany empty out and stop logging, we should not produce any
# more log entries. So, we set the log level back to a very high value.

log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);

if (verbosity >= 3):
    eprint("Received interrupt, emptying ring buffer");

while True:
    prev_rcvd = nread();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == nread()):
        break;

time.sleep(0.1)

while True:
    prev_rcvd = nread();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == nread()):
        break;

do_write();
end_op()
time.sleep(0.01)

eprint('======================== Summary from eauditd.py ========================')

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

rb_drops = stats[0];
if (rb_drops > 0) and (verbosity > 0):
    eprint("*** Dropped data *** Ring buffer output failed %d times" % rb_drops)

bytes_sent = stats[1]
bytes_got = nread();
msgs_sent = stats[2] and stats[2] or stats[2]+1;
if msgs_sent == 0:
    msgs_sent = 0.01
if totsc == 0:
    totsc = 0.01
wakes_sent = stats[3] and stats[3] or stats[3]+1;
nflushes = stats[51];
nflushchecks = stats[52];
if (verbosity > 0):
#  if prt_summary:
    eprint("%s Calls, %siB (%s lost), Size: call=%d record=%d\n" % \
      (pp(totsc), pp(bytes_got), pp(bytes_sent-bytes_got), \
       bytes_sent/totsc, bytes_sent/msgs_sent));

if verbosity >= 2:
  eprint("%d ringbuf calls with wakeup flag, %d without, %d actual wakes" % 
       (wakes_sent, msgs_sent-wakes_sent, wakes_rcvd));
  if nflushes > 0:
      eprint("%d flushes of an idle core's cache (%0.3f%% of syscalls)" \
             % (nflushes, nflushes*100.0/totsc))

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

idgen = stats[29];
idgenerrs = stats[28];
if (idgen > 0) and (verbosity >= 2):
    if (verbosity > 2 and idgenerrs > 0) or idgenerrs*300 > idgen:
        eprint("*** %d fdtoid calls, %d errors ***" % (idgen, idgenerrs))

for i in range(23, 28):
    ct = stats[i]
    if (verbosity > 2 and ct > 0)  or (verbosity == 2 and ct*1000000 > idgen):
        eprint("*** %0.3f%% id gen errors of kind %d ***" % (ct*100.0/idgen, i))

ct = stats[48]
if (verbosity >= 2 and ct > 0):
    eprint("*** %d syscalls lost due to lock contention: ***" % (ct))

if tamper_detect:
    sf_key_window = stats[59]
    sf_zero_key   = stats[60]
    sf_tailcall_sign_record = stats[61]
    sf_map_lookup = stats[62]
    sf_tailcall_umac_start = stats[63]
    sf_tailcall_umac_cont = stats[64]
    sf_tailcall = (sf_tailcall_sign_record + sf_tailcall_umac_start
                   + sf_tailcall_umac_cont)
    ct = sf_key_window + sf_zero_key + sf_tailcall + sf_map_lookup
    if (verbosity >= 2 and ct > 0):
        eprint("*** %d syscalls MAC generation failure: ***" % (ct))
        eprint("      key window exhaustion: %d" % sf_key_window)
        eprint("      zero/uninitialized key: %d" % sf_zero_key)
        eprint("      tail call failure: %d" % sf_tailcall)
        eprint("        sign-record handoff: %d" % sf_tailcall_sign_record)
        eprint("        UMAC start handoff: %d" % sf_tailcall_umac_start)
        eprint("        UMAC continuation: %d" % sf_tailcall_umac_cont)
        eprint("      map lookup failure: %d" % sf_map_lookup)

execve_tailcall_argv_start = stats[65]
execve_tailcall_argv_cont = stats[66]
execve_tailcall_envp_start = stats[67]
execve_tailcall_envp_cont = stats[68]
ct = (execve_tailcall_argv_start + execve_tailcall_argv_cont
      + execve_tailcall_envp_start + execve_tailcall_envp_cont)
if verbosity >= 2 and ct > 0:
    eprint("*** %d execve tail call failures: ***" % ct)
    eprint("      argv start: %d" % execve_tailcall_argv_start)
    eprint("      argv continuation: %d" % execve_tailcall_argv_cont)
    eprint("      envp start: %d" % execve_tailcall_envp_start)
    eprint("      envp continuation: %d" % execve_tailcall_envp_cont)

ct = stats[49]
if (verbosity >= 2 and ct > 0):
    eprint("*** %d unexpected map lookup failures: ***" % (ct))

arg_lookup_fail = stats[50] - unexp_lkp_fail
if (verbosity > 0 and arg_lookup_fail*500 > totsc): 
    eprint("*** %0.2f%% unexpected argument lookup failures: ***" % 
           (arg_lookup_fail*100.0/totsc));
    if arg_lookup_fail*200 > totsc: 
        eprint("\tSysCall #errors")
        errcount = b["errcount"].values()
        for i in range(0, len(ierrcount)):
            e = errcount[i].value - ierrcount[i].value
            if e > 0:
                eprint("\t%d\t%d" % (i, e))

if machine_friendly:
    eprint("%ssyscalls %d" % (machine_friendly, totsc))
    eprint("%ssent %d" % (machine_friendly, bytes_sent))
    eprint("%slost %d" % (machine_friendly, bytes_sent-bytes_got))
    eprint("%savgcallsize %d" % (machine_friendly, bytes_sent/totsc))
    eprint("%savgcachesize %d" % (machine_friendly, bytes_sent/msgs_sent))
    eprint("%savgp %d" % (machine_friendly, (totsc+msgs_sent-1)/msgs_sent))
    eprint("%savgw %d" % (machine_friendly, (msgs_sent+wakes_rcvd-1)/wakes_rcvd))
    if ID_NOT_FD:
        eprint("%sid_fail %0.2f%%" % (machine_friendly, (idgenerrs*100)/idgen))
    eprint("%sarg_fail %0.2f%%" % (machine_friendly, (arg_lookup_fail*100)/totsc))

if verbosity > 2:
    #b["fduse"].print_log2_hist("fd#")
    #print(" ")
    b["msg_delivery_lag"].print_log2_hist("queued messages (#)")
    b["cache_flush_lag"].print_log2_hist("cache_flush_lag (us)")

eprint('====================== END Summary from eauditd.py ======================')
time.sleep(0.01)
