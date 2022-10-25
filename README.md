# Samples showing kernel kprobe, userspace uprobe and USDT tracing

Samples illustrate how to do kernel and userspace tracing.

- do_sysinfo: kprobe tracing
- mallocation: userspace uprobe tracing
- usdt_example: userspace USDT tracing

## Building

Requires clang/llvm > 13 and bpftool, libbpf > 0.8; Makefile assumes
the latter two are built from source and installed in /usr/local.

## do_sysinfo

Simple BPF program that traces the do_sysinfo function and
triggers it via a sysinfo() syscall.  To run:

```
$ sudo do_sysinfo
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
      do_sysinfo-26268   [002] d..31 702610.777723: bpf_trace_printk: called do_sysinfo
```

## mallocations

BPF program that traces mallocs by process counting malloc()ed bytes (not freed
ones so counts are cumulative).  Displays counts by process:

```
$ sudo ./mallocation 
Hit Ctrl+C to exit

                 PID      MALLOCS (bytes)
                4283                   89
                7958               521994
                1306                    7
                1263                47593
                2291               322337
                3758                    4
               14384              1225699
                1267                 1585
                4643                71799
                1571               980092
               26563               950280
                2541                   64
                2695               440104
                4582                 2123
                2648                54858
                4118                 5529
               26555                   74
                4055                   80
                4047                19724
                1261                36745
```

## usdt_example

Simple program that defines a USDT static probe point and traces its
execution; the probe simply records how many arguments the program was run
with (i.e. argc)

```
$ sudo ./usdt_example
Hit return to call probe with nargs 1...

Got nargs 1 from USDT bpf program for example/args event

```
