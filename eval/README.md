At the top-level of this directory are the shell scripts used for measuring the
performance of **eaudit**. 

* **bmrunall** in a simple top-level script that runs all the benchmarks once and
   collects information such as runtimes, data volume and loss, and the realized
   values of performance parameters such as w and p discussed in our paper. It
   repeatedly invokes bmrun for each benchmark. Parameters to bmrun are
   hard-coded in bmrunall, so the script needs to be edited if a different
   set of parameter values is desired.

* **bmrun** is a more complex script that runs a specified benchmark with and 
   without eaudit, and collects various measurements, and outputs them into
   a csv file mentioned on the command line.

Both **bmrun** and **bmrunall** includes usage messages that will be printed when the 
required number of parameters is not provided. They can use the following
benchmarks. In most cases, a benchmark X is run by executing the script run_X.

* **find:** prints all plainfile names within /usr (or a specified directory)

* **httperf:** a benchmark for web servers. See httperf/ directory for 
   mode details.

* **kernel:** compiles the Linux kernel, which must forst be downloaded into the
   subdirectory kernel/. Alternatively, kernel/ can be a symlink to the location
   containing the kernel source code.

* **postmark:** a well-known file system benchmark intended to capture the I/O
   patterns of a mail server. See postmark/ directory for more information.

* **rdwr:** a C-program that calls read and write in a tight loop. It is designed
   with the explicit goal of maximizing the rate of syscalls, and is intended
   to capture the worst-case for peformance of syscall logging tools. Its
   source code is in the subdirectory rdwr/.

* **shbm:** a benchmark intended to capture the behavior of typical shell scripts.
   Specifically, shbm repeatedly execve's /bin/echo.

* **tar:** uses tar to archive /usr/src or a specified directory.

In addition, there are subdirectories for some of the alternative syscall
logging tools that we have compared with eaudit, including sysdig, tetragon and
tracee. These directories generally contain configuration files and directories
that should be largely self-explanatory, but are not further documented here.

Finally, there are scripts for some of the other measurements appearing in the
paper, e.g., data loss reported by other tools, log tampering window, etc. 
These are provided with the hope that they will aid in reproducing our results,
but a full documentation may be lacking. (But again, the scripts are not too
complex.)

## Log Tampering script Note:

 Be aware that our log tampering measurements no
longer require the use of signals to generate tamper windows, as mentioned in
the eAudit paper. Instead, our system generates these windows internally, 
in a periodic manner. 

## Additional instructions for httperf and kernel benchmarks:

For the kernel benchmark, use wget to get the latest linux kernel distro
(https://git.kernel.org/torvalds/t/linux-6.5-rc7.tar.gz), untar it into the
directory kernel/. For httperf, first install nginx (e.g., sudo apt install
nginx) and configure nginx to serve static content. This content can either be
downloaded from our lab web site (http://seclab.cs.sunysb.edu/seclab/), or you
can supply your own content. In the latter case, the file uris.txt should be
appropriately updated. You should also verify that run_httperf will work for
you, or else you may have to modify it a bit.

## Reproduction of Results: 

The contents of this directory are designed to
facilitate results reproduction. But there are many caveats in this regard:

* Performance numbers will vary with the hardware platform and operating system
   version. These changes can be significant in some cases, so it would be
   difficult to reproduce the exact numbers. Nevertheless, these platform
   variations should be small enough that they don't impact the conclusions
   made in the paper.

* In addition to platform characteristics such as the number of cores, the type
   of storage can have a significant impact. We try to mitigate this by sizing
   data sets so that most of the benchmarks perform their I/O operations on the
   buffer caches. (However, this does not apply to all benchmarks, e.g.,
   postmark and kernel.)

* Performance observed on a VM image will vary significantly with the
   chracteristics of the underlying hardware platform on which the VM is run.

* Some of the tools we compare with are themselves under active development.
   Our numbers correspond to the versions we downloaded between November 2022
   (e.g., Auditd, CamFlow, ProvBPF) and April 2023 (Sysdig, Tracee, Tetragon),
   but newer versions may produce different results.

* Peformance measurements on modern processors is very challenging because of
   the interaction between power and thermal management features of the
   processors and the OS, and the characteristics of the benchmarks. Our scripts
   attempt to mitigate some of these problems by starting with a warm up phase,
   and then running a benchmark with and without eaudit back to back. Another
   measure is to reboot the machine before a measurement to ensure a clean,
   repeatable starting state.

* Measurement scripts produce only a single measurement. They need to be run
   multiple times so that one can average across multiple measurements.

