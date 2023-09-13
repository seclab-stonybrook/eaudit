

**eAudit** is compatible with recent Linux distributions. It is based on the
BCC toolkit for developing ebpf applications. Although BCC may be available
as a binary package, it is preferable to install it from source. This is because
the binary packages can be years behind the current version and hence may not 
be compatible with **eAudit**. 

One way to check if you already have BCC is to run **ecapd**, e.g., issue the
following commands from the top-level **eaudit** directory:

    abc@xyz> make all
    <... compilation related messages ...>
    abc@xyz> ./ecapd
    [sudo] password for abc: <type your password>
    Logprinter: 0M records, average size 8

If you see a dialog such as the above and the line beginning with "Logprinter"
is printed, then you are all set. Keep in mind that you may have to wait for
about 10 seconds before the message is printed.

If you don't see the "Logprinter: ..." message, chances are that BCC is not
installed. In this case, run the bcc_install.sh. When this script succeeds,
you should be all set: you can run **ecapd **now.
