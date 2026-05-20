
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

This is the **eAudit** suite for recording provenance-related system calls on Linux using the eBPF framework. It integrates three research systems: **eAudit** for high-throughput, low-overhead "always on" audit logging (IEEE S&P 2024); **WinSeal** for tamper protection of provenance logs with prevention and detection capabilities (IEEE S&P 2026); and **Improv**, a user-level post-processor that bridges causal gaps by querying the kernel for missing provenance context (PRISM 2026).

This release supports creating record files from captured audit data, which can 
be replayed by the host program for analysis.

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

There are three top-level programs:

  * **ecapd** — captures system calls and writes them to a log file.
  * **eauditd** — captures system calls with the added ability to create record files, performing online gap-filling to enrich provenance logs by querying the kernel.
  * **eaudit** — offline parser that reads captured log files and produces human-readable output.

Being based on **eBPF**, **ecapd** and **eauditd** require root privilege to run. All programs support a **-h** option that prints a help message documenting the command-line options.

## Behind the scene

**ecapd**  is a wrapper shell script that invokes **eauditd.py**,
which loads and manages the **ebpf** code in **eauditk.c**. **eauditd.py** also loads 
the code from eauditd.C and sets it up to read the captured data (from
**ebpf**'s ring buffer) and write it into the capture file. 

**eauditd** invokes **eParser.C** online to parse each event as it arrives from the ring buffer. Parsed events are passed to **eConsumer.C**, which pairs syscall entry and exit records, and fills in missing provenance information by querying `/proc` for process details such as executable path, working directory, and command-line arguments. The enriched events are written in a structured record format consumable by the host analysis program.

**eaudit.C** and **eParser.C** contain the code that compiles into **eaudit**, the program
that parses capture files and produces a human-readable output. **eauditk.c** is
compiled on the fly and loaded into the kernel by **eauditd.py**.

## Publication

* <a href="http://seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf">eAudit: A Fast, Scalable and Deployable Audit Data Collection System</a>
  R. Sekar, Hanke Kimm, and Rohit Aich
  Stony Brook University, NY, USA. IEEE S&P 2024.

* <a href="https://www.computer.org/csdl/proceedings-article/sp/2026/606500b706/2bojwlSBc2Y">Sealing the Window: Efficient Tamper Protection for Provenance Logs</a>
  Sagar Mishra and R. Sekar
  Stony Brook University, NY, USA. IEEE S&P 2026, pp. 1707–1724. DOI: 10.1109/SP63933.2026.00092

* <a href="https://www.ndss-symposium.org/wp-content/uploads/prism2026-23.pdf">Minding the Gap: Bridging Causal Disconnects in System Provenance</a>
  Hanke Kimm, Sagar Mishra, and R. Sekar
  Stony Brook University, NY, USA. PRISM 2026.

## Copyright

********************************************************************************
 Copyright (c) 2022-23, R. Sekar and Secure Systems Lab, Stony Brook University
********************************************************************************
