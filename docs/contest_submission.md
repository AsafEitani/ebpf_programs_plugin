## Volatility plugin contest 2023 Submissions - eBPF programs & rootkit detection
### Asaf Eitani

<br>

## Table of content
<!-- TOC start -->
- [Abstract](#abstract)
- [Previous work](#previous-work)
- [Changes/additions to Volatility core plugins](#volatility-changes)
  - [Changes made in the Volatility framework](#volatility-framework-changes)
- [Rootkit detection](#ebpf)
- [Why should I win the contest?](#why-should-I-win-the-contest)
<!-- TOC end -->

<br>

## Abstract <!-- TOC --><a name="abstract"></a>
> eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in an operating system kernel. It is used to safely and efficiently extend the capabilities of the kernel without requiring to change kernel source code or load kernel modules.
The objective of this project is to create a Volatility 3 plugin for eBPF program detection. Further more, this is a direct continuation of the 2022 submission <a href="https://github.com/AsafEitani/rootkit_plugins/tree/main">Rootkit Plugins</a>, by adding a way of eBPF rootkit detection.
This plugin complete the suite of rootkit detection by supporting the latest type of rootkits.

An overview of how the plugin work is supplied below.

<br>

## Previous work <!-- TOC --><a name="previous-work"></a>
This submission made some usage with the 2021 BlackHat submission - <a href="https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fixing-A-Memory-Forensics-Blind-Spot-Linux-Kernel-Tracing-wp.pdf">Fixing a Memory Forensics Blind Spot: Linux
Kernel Tracing</a> by Andrew Case and Golden G. Richard III, which present a high level overview of written, but never released plugins.
This plugin operates different than the suggested plugins in that artical.
<br>


## eBPF programs detection <!-- TOC --><a name="ebpf"></a>

<br>

The `ebpf_programs` plugin is used to detect loaded eBPF programs, as well as eBPF rootkits presence.
eBPF rootkits are a new type of rootkits that makes use of eBPF helper functions to modify the system default behavior in order to hide artifacts, exfiltrate information or actively effect the system.
The eBPF helpers used to modify the system behavior are as follows:
- `bpf_probe_write_user`
- `bpf_override_return`
- `bpf_skb_store_bytes`
- `bpf_skb_pull_data`
- `bpf_send_signal`


The plugin determines if any eBPF program is using any of those helpers by disassembling the eBPF function after JIT.
The plugin is also able to dump the eBPF function as binary for further investigation using the `dump` flag.
For each eBPF program the following information is displayed:('Name', str), ('Full Name', str), ('Type', str), ('Jited Bytes Length', int),
                                   ('Load Time', datetime), ("Used Helpers", str),
                                   ("Rootkit Behavior", bool), ("Dumped Filename", str)
- `Name` - The name of the eBPF program.
- `Full Name` - The full name of the eBPF program, including a prefix and the program tag.
- `Type` - The eBPF program type according to <a href="https://elixir.bootlin.com/linux/v5.15/source/include/uapi/linux/bpf.h#L919">the Linux kernel</a>
- `Jited Bytes Length` - The length of the bytes generated after the JIT process.
- `Load Time` - The time of the eBPF program load.
- `Used Helpers` - A list of the used helpers in the program. obtained using `capstone` and a disassembly of the eBPF program.
- `Rootkit Behavior` - A boolean indicating if the program is suspected as a rootkit.
- `Dumped Filename` - The name of the dumped program if the `dump` flag was used.


## Why should I win the contest? <!-- TOC --><a name="why-should-I-win-the-contest"></a>
As a enthusiastic supporter of the Volatility framework and a security researcher, I have been using the framework for years on Windows memory images.
I recently moved into Linux research and found the lack of plugins in Volatility3 to be disturbing, resulting in the development of a few rootkit detection plugins in 2022 which won the 2nd place in the yearly competition.
This submission is a direct continuation of last years submission, completing the rootkit cover of Volatility 3 for advanced Linux rootkits.
Along the way this submission enables users to display the loaded eBPF programs and their information.

I hope that by adding those capabilities to Volatility3, more eBPF rootkits will be found and analyzed as the Volatility framework has a unique advantage for detecting those advanced threats.


Thanks for reading :)
