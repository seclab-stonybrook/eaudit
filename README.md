
<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-software">About the software</a>
    </li>
    <li>
      <a href="#prerequisites-and-installation">Prerequisites and Installation</a>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#behind-the-scene">Behind the scene</a></li>
    <li><a href="#publication">Publication</a></li>
    <li><a href="#copyright">Copyright</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>


## About the software

This is the **eAudit** suite for recording provenance-related system calls using the
Linux ebpf framework, and to subsequently print this information in a human-readable format. This initial release accompanies our research <a href="#publication">paper</a>  at
IEEE Symposium on Security and Privacy, 2024.

System call logs are the last line of defense against sophisticated cyber attacks, providing a detailed and causally complete record for post-attack investigation. This use requires logging to be enabled at all times, but unfortunately, existing systems for system call logging do not seem to have been designed or engineered for such use. Consequently, they are prone to losing a
large fraction of events during peak loads, and moreover, introduce significant performance and storage overheads. We developed eAudit to mitigate these drawbacks, and to enable "always on" audit logging. Our specific goals are to:

  * enable systems to support peak workloads without a significant slowdown,
  * avoid losing system calls at any possible system load, and 
  * minimize the latency for logging.

We anticipate continued development of this software, with future additions
focused on reducing the data volume, further improving the performance and
robustness, and providing an API for system call analysis tools.

This software is organized as follows:

  * The top-level directory contains most of the source code, with the
     remaining code appearing in the lib/ directory.

  * The directory eval/ contains benchmarks, scripts and tools used in our
     evaluation in our paper.


## License

This software release is governed by **GPL v3** copyright license.


## Prerequisites and Installation

See the file **INSTALL**.

## Usage

There are two top-level programs: **ecapd** and **eaudit**. **ecapd** is for
logging system calls, while **eaudit** is used to parse/print the collected logs in
a human readable format. Being based on **ebpf**, **ecapd** requires root privilege to
run. Both programs support a **-h** option that prints a help message documenting the
command-line options.

## Behind the scene

**ecapd**  is a wrapper shell script that invokes **eauditd.py**,
which loads and manages the **ebpf** code in **eauditk.c**. **eauditd.py** also loads 
the code from eauditd.C and sets it up to read the captured data (from
**ebpf**'s ring buffer) and write it into the capture file. 

**eaudit.C** and **eParser.C** contain the code that compiles into **eaudit**, the program
that parses capture files and produces a human-readable output. **eauditk.c** is
compiled on the fly and loaded into the kernel by **eauditd.py**.

## Publication

* <a href="http://seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf">eAudit: A Fast, Scalable and Deployable Audit Data Collection System </a>
  R. Sekar, Hanke Kimm, and Rohit Aich
  Stony Brook University, NY, USA.

## Copyright

********************************************************************************
 Copyright (c) 2022-23, R. Sekar and Secure Systems Lab, Stony Brook University
********************************************************************************
