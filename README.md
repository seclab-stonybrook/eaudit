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
    <li><a href="#prevention-and-detection-modes">Prevention and Detection Modes</a></li>
    <li><a href="#tamper-window-evaluation-scripts">Tamper Window Evaluation Scripts</a></li>
    <li><a href="#behind-the-scene">Behind the scene</a></li>
    <li><a href="#publication">Publication</a></li>
    <li><a href="#copyright">Copyright</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>


## About this software

This is the **development** branch of **eAudit** and **Winseal** suite for recording
provenance-related system calls using the Linux ebpf framework, and to
subsequently print this information in a human-readable format.

System call logs are the last line of defense against sophisticated cyber
attacks, providing a detailed and causally complete record for post-attack
investigation. This use requires logging to be enabled at all times, but
unfortunately, existing systems for system call logging do not seem to have been
designed or engineered for such use. Consequently, they are prone to losing a
large fraction of events during peak loads, and moreover, introduce significant
performance and storage overheads. We developed eAudit to mitigate these
drawbacks, and to enable "always on" audit logging. Our specific goals are to:

  * enable systems to support peak workloads without a significant slowdown,
  * avoid losing system calls at any possible system load, 
  * extend eAudit with prevention and detection modes that protect audit logs
    against tampering, and
  * minimize the latency for logging.

This software is organized as follows:

  * The top-level directory contains most of the source code, with the
     remaining code appearing in the lib/ directory.
  * The directory eval/ contains benchmarks, scripts and tools for evaluation.


## License

This is proprietary software. All rights reserved. 

## Prerequisites and Installation

See the file **INSTALL**.

## Usage

There are two top-level programs: **ecapd** and **eaudit**. **ecapd** is for
logging system calls, while **eaudit** is used to parse/print the collected logs
in a human readable format. Being based on **ebpf**, **ecapd** requires root
privilege to run. Both programs support a **-h** option that prints a help
message documenting the command-line options.

## Prevention and Detection Modes

This release extends eAudit from high-throughput audit collection to audit-log
tamper protection. The new support is exposed through two operating modes:

* **prevention** is the default mode. It runs eAudit in its normal logging
  configuration and is used to evaluate how buffering and flushing policies
  reduce the window in which audit data can be modified before it is preserved.
  Scripts pass this mode by using the argument `prevention`.
* **detection** enables tamper-detection support. The logger signs records with
  UMAC3 metadata by passing `-H` to **ecapd**, and the resulting log can be
  parsed with `eaudit -L -V` so the parser verifies the MACs and detects
  modified audit records.

The mode is exposed as the `defense` argument in the tamper-window scripts:

```
prevention | detection
```

## Tamper Window Evaluation Scripts

Tamper-window measurement scripts live in `eval/tamper_win/`:

* `low_load_tw` runs only the logger for a fixed duration and then invokes
  **eaudit** to compute the average tamper window.
* `high_load_tw` runs a benchmark workload while the logger is active and then
  invokes **eaudit** to compute the average tamper window.

The helper scripts used by these entry points are in `eval/`:

* `bgrun_remote`
* `bmremote`
* `bmrunall-remote`

`bmremote` is the main benchmark helper script. Its output includes the
benchmark overhead percentage column (`ohead`). Use the script's parameter
information to pass the correct values for a specific experiment.

The scripts resolve paths relative to their own locations. `ecapd` and
`eaudit` are run from the repository root, and benchmark commands such as
`run_httperf` are resolved under `eval/`.

The generated CSV includes the selected defense mode, log destination, trial
number, and average tamper-window value. See each script's parameter
information for the correct values to pass for a specific experiment.

## Behind the scene

**ecapd** is a wrapper shell script that invokes **eauditd.py**, which loads and
manages the **ebpf** code in **eauditk.c**. **eauditd.py** also loads the code
from eauditd.C and sets it up to read the captured data (from **ebpf**'s ring
buffer) and write it into the capture file.

**eaudit.C** and **eParser.C** contain the code that compiles into **eaudit**,
the program that parses capture files and produces a human-readable output.
**eauditk.c** is compiled on the fly and loaded into the kernel by
**eauditd.py**.

## Publication

* <a href="http://seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf">eAudit: A Fast,
  Scalable and Deployable Audit Data Collection System </a> R. Sekar, Hanke
  Kimm, and Rohit Aich Stony Brook University, NY, USA.

## Copyright

********************************************************************************
 Copyright (c) 2022-23, R. Sekar and Secure Systems Lab, Stony Brook University
********************************************************************************
