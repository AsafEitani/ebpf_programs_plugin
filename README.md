## Volatility3 eBPF programs & rootkit detection plugin
<br />

### Project Description

This repo contains a Volatility3 plugin that detects loaded eBPF programs and indicates for each if they are suspected as an eBPF rootkit.

[A full (but readable) explanation of plugin details can be found in the contest submission document](docs/contest_submission.md)



### Plugins

- **`ebpf_programs`** - The `ebpf_programs` plugin is used to detect loaded eBPF programs, along with their information (loading time, name, type and used helpers), a boolean indicating if a program is suspected as an eBPF rootkit. The plugin also allows dumping of BPF programs (after they have gone through JIT).


### ✔️ Prerequisites:

- Python 3
- Volatility 3
- capstone

Install on Linux using these commands:

```bash
apt install python3
# clone from repo
git clone https://github.com/volatilityfoundation/volatility3.git
pip3 install capstone
# or install as a module
pip3 install volatility3 capstone
```

### ⚙ Installation

Copy the `ebpf_programs.py` file to your Volatility 3 directory under `volatility3/volatility3/framework/plugins/linux`.


### Usage

`python3 ./vol.py -f <image> linux.ebpf_programs --name=<optional sprcific name> --dump`
A `name` and `dump` flags can be used to filter by name or dump the program binary(after JIT) to disk.
