# HPC

HPC scripts for research infra and file system auto tuning using ebpf


### Tuning script

[tunig scripy](./ebpf-trace-filesystem-tuning.py) tunes the file system by characterising file system workload automatically.

**Dynamic Parameter Tuning**

- Large Sequential I/O (CFD, climate): deadline scheduler, large read-ahead
- Small Random I/O (databases, some ML): noop scheduler, small read-ahead
- Write-heavy: optimized dirty page ratios
- Read-heavy: enhanced caching parameters
