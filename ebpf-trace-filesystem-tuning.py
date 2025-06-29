#!/usr/bin/env python3
"""
eBPF-based HPC Storage Auto-Tuner
Dynamically characterizes workload patterns and tunes system parameters
"""

from bcc import BPF
import time
import json
import subprocess
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Tuple
import threading

@dataclass
class WorkloadProfile:
    read_ratio: float
    write_ratio: float
    avg_io_size: int
    seq_ratio: float
    random_ratio: float
    iops: int
    bandwidth_mb: int
    latency_ms: float

class HpcStorageTuner:
    def __init__(self, device_path="/dev/md0", mount_point="/hpc"):
        self.device_path = device_path
        self.mount_point = mount_point
        self.metrics_history = deque(maxlen=60)  # 1 minute history
        self.current_profile = None
        self.tuning_active = False
        
        # eBPF program for I/O tracing
        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/blkdev.h>
        #include <linux/blk-mq.h>

        // Data structures for tracking I/O patterns
        struct io_event {
            u64 ts;
            u32 pid;
            u32 size;
            u64 sector;
            u32 rwbs;
            char comm[TASK_COMM_LEN];
        };

        struct io_stats {
            u64 read_count;
            u64 write_count;
            u64 read_bytes;
            u64 write_bytes;
            u64 total_latency;
            u64 seq_reads;
            u64 seq_writes;
            u64 random_reads;
            u64 random_writes;
        };

        // Maps for collecting metrics
        BPF_HASH(io_start, struct request *, u64);
        BPF_HASH(stats, u32, struct io_stats);
        BPF_PERF_OUTPUT(events);

        // Track I/O request start
        int trace_req_start(struct pt_regs *ctx, struct request *req) {
            u64 ts = bpf_ktime_get_ns();
            io_start.update(&req, &ts);
            return 0;
        }

        // Track I/O completion and analyze patterns
        int trace_req_completion(struct pt_regs *ctx, struct request *req) {
            u64 *start_ts = io_start.lookup(&req);
            if (!start_ts) return 0;
            
            u64 end_ts = bpf_ktime_get_ns();
            u64 latency = end_ts - *start_ts;
            
            struct io_event event = {};
            event.ts = *start_ts;
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.size = req->__data_len;
            event.sector = req->__sector;
            event.rwbs = 0;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            
            // Determine if read or write
            if (req->cmd_flags & REQ_WRITE) {
                event.rwbs = 1; // Write
            }
            
            events.perf_submit(ctx, &event, sizeof(event));
            
            // Update statistics
            u32 key = 0;
            struct io_stats *stat = stats.lookup(&key);
            if (!stat) {
                struct io_stats new_stat = {};
                stats.update(&key, &new_stat);
                stat = stats.lookup(&key);
            }
            
            if (stat) {
                if (event.rwbs == 1) {
                    __sync_fetch_and_add(&stat->write_count, 1);
                    __sync_fetch_and_add(&stat->write_bytes, event.size);
                } else {
                    __sync_fetch_and_add(&stat->read_count, 1);
                    __sync_fetch_and_add(&stat->read_bytes, event.size);
                }
                __sync_fetch_and_add(&stat->total_latency, latency);
            }
            
            io_start.delete(&req);
            return 0;
        }
        """
        
        # Initialize eBPF
        self.bpf = BPF(text=self.bpf_program)
        self.bpf.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
        self.bpf.attach_kprobe(event="blk_account_io_completion", fn_name="trace_req_completion")
        
        # Storage for sequential access detection
        self.last_sectors = defaultdict(int)
        
    def process_io_event(self, cpu, data, size):
        """Process I/O events from eBPF"""
        event = self.bpf["events"].event(data)
        
        # Detect sequential vs random access
        comm = event.comm.decode('utf-8', 'replace')
        if comm in self.last_sectors:
            if abs(event.sector - self.last_sectors[comm]) <= 16:  # Sequential threshold
                is_sequential = True
            else:
                is_sequential = False
        else:
            is_sequential = False
            
        self.last_sectors[comm] = event.sector
        
        # Store event for analysis
        self.store_event(event, is_sequential)
    
    def store_event(self, event, is_sequential):
        """Store processed event for workload characterization"""
        event_data = {
            'timestamp': event.ts,
            'pid': event.pid,
            'size': event.size,
            'sector': event.sector,
            'is_write': bool(event.rwbs),
            'is_sequential': is_sequential,
            'command': event.comm.decode('utf-8', 'replace')
        }
        
        # Add to metrics (in real implementation, use a more efficient data structure)
        if not hasattr(self, 'recent_events'):
            self.recent_events = deque(maxlen=1000)
        self.recent_events.append(event_data)
    
    def characterize_workload(self) -> WorkloadProfile:
        """Analyze recent I/O patterns and characterize workload"""
        if not hasattr(self, 'recent_events') or len(self.recent_events) < 10:
            return None
            
        total_events = len(self.recent_events)
        read_count = sum(1 for e in self.recent_events if not e['is_write'])
        write_count = total_events - read_count
        
        total_bytes = sum(e['size'] for e in self.recent_events)
        seq_count = sum(1 for e in self.recent_events if e['is_sequential'])
        
        avg_io_size = total_bytes // total_events if total_events > 0 else 0
        
        # Calculate ratios
        read_ratio = read_count / total_events if total_events > 0 else 0
        write_ratio = write_count / total_events if total_events > 0 else 0
        seq_ratio = seq_count / total_events if total_events > 0 else 0
        random_ratio = 1 - seq_ratio
        
        # Estimate IOPS and bandwidth (simplified)
        time_window = 5  # 5 second window
        iops = total_events // time_window
        bandwidth_mb = (total_bytes // (1024 * 1024)) // time_window
        
        # Get latency from eBPF stats
        stats = self.bpf["stats"]
        key = stats.Key(0)
        try:
            stat = stats[key]
            avg_latency = (stat.total_latency / (stat.read_count + stat.write_count)) / 1000000  # Convert to ms
        except:
            avg_latency = 0
        
        return WorkloadProfile(
            read_ratio=read_ratio,
            write_ratio=write_ratio,
            avg_io_size=avg_io_size,
            seq_ratio=seq_ratio,
            random_ratio=random_ratio,
            iops=iops,
            bandwidth_mb=bandwidth_mb,
            latency_ms=avg_latency
        )
    
    def apply_tuning(self, profile: WorkloadProfile):
        """Apply system tuning based on workload profile"""
        tuning_actions = []
        
        # Determine workload type and tune accordingly
        if profile.seq_ratio > 0.8 and profile.avg_io_size > 64*1024:
            # Large sequential I/O workload (CFD, climate modeling)
            if profile.avg_io_size > 1024*1024:  # Very large I/O (>1MB)
                # Aggressive tuning for massive datasets
                tuning_actions.extend([
                    ("scheduler", "deadline"),
                    ("read_ahead", "32768"),    # 32MB read-ahead
                    ("nr_requests", "1024"),    # Large request queue
                    ("queue_depth", "64"),      # Deep queue for throughput
                    ("max_sectors_kb", "4096")  # 4MB max I/O size
                ])
            else:
                # Standard large sequential I/O
                tuning_actions.extend([
                    ("scheduler", "deadline"),
                    ("read_ahead", "16384"),    # 16MB read-ahead
                    ("nr_requests", "512"),
                    ("queue_depth", "32")
                ])
            
        elif profile.random_ratio > 0.8 and profile.avg_io_size < 4*1024:
            # Small random I/O workload (database-like, some ML)
            tuning_actions.extend([
                ("scheduler", "noop"),
                ("read_ahead", "512"),
                ("nr_requests", "128"),
                ("queue_depth", "64")
            ])
            
        elif profile.write_ratio > 0.7:
            # Write-heavy workload
            tuning_actions.extend([
                ("scheduler", "deadline"),
                ("dirty_ratio", "20"),
                ("dirty_background_ratio", "10"),
                ("dirty_expire_centisecs", "1500")
            ])
            
        elif profile.read_ratio > 0.8:
            # Read-heavy workload
            tuning_actions.extend([
                ("scheduler", "deadline"),
                ("read_ahead", "8192"),
                ("vfs_cache_pressure", "50")
            ])
        
        # Apply tuning parameters
        for param, value in tuning_actions:
            try:
                self.set_system_parameter(param, value)
                print(f"Applied tuning: {param} = {value}")
            except Exception as e:
                print(f"Failed to apply {param}: {e}")
    
    def set_system_parameter(self, param: str, value: str):
        """Set system tuning parameters"""
        device_name = os.path.basename(self.device_path)
        
        param_map = {
            "scheduler": f"/sys/block/{device_name}/queue/scheduler",
            "read_ahead": f"/sys/block/{device_name}/queue/read_ahead_kb",
            "nr_requests": f"/sys/block/{device_name}/queue/nr_requests",
            "queue_depth": f"/sys/block/{device_name}/queue/queue_depth",
            "max_sectors_kb": f"/sys/block/{device_name}/queue/max_sectors_kb",
            "dirty_ratio": "/proc/sys/vm/dirty_ratio",
            "dirty_background_ratio": "/proc/sys/vm/dirty_background_ratio",
            "dirty_expire_centisecs": "/proc/sys/vm/dirty_expire_centisecs",
            "vfs_cache_pressure": "/proc/sys/vm/vfs_cache_pressure"
        }
        
        if param in param_map:
            if param == "scheduler":
                # Special handling for scheduler
                subprocess.run(f"echo {value} > {param_map[param]}", shell=True, check=True)
            else:
                with open(param_map[param], 'w') as f:
                    f.write(value)
    
    def monitor_and_tune(self, interval=5):
        """Main monitoring and tuning loop"""
        print("Starting eBPF-based HPC storage auto-tuner...")
        
        # Start eBPF event processing
        self.bpf["events"].open_perf_buffer(self.process_io_event)
        
        while True:
            try:
                # Poll for events
                self.bpf.perf_buffer_poll(timeout=interval*1000)
                
                # Characterize workload
                profile = self.characterize_workload()
                if profile:
                    print(f"Workload Profile: R/W={profile.read_ratio:.2f}/{profile.write_ratio:.2f}, "
                          f"Seq/Rand={profile.seq_ratio:.2f}/{profile.random_ratio:.2f}, "
                          f"Avg IO={profile.avg_io_size}B, IOPS={profile.iops}, "
                          f"BW={profile.bandwidth_mb}MB/s, Lat={profile.latency_ms:.2f}ms")
                    
                    # Apply tuning if workload has changed significantly
                    if self.should_retune(profile):
                        self.apply_tuning(profile)
                        self.current_profile = profile
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("Shutting down...")
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(interval)
    
    def should_retune(self, new_profile: WorkloadProfile) -> bool:
        """Determine if system should be retuned based on workload changes"""
        if not self.current_profile:
            return True
            
        # Define thresholds for significant changes
        thresholds = {
            'read_ratio': 0.2,
            'seq_ratio': 0.3,
            'avg_io_size': 0.5,  # 50% change
            'iops': 0.4
        }
        
        current = self.current_profile
        
        # Check for significant changes
        if abs(new_profile.read_ratio - current.read_ratio) > thresholds['read_ratio']:
            return True
        if abs(new_profile.seq_ratio - current.seq_ratio) > thresholds['seq_ratio']:
            return True
        if abs(new_profile.avg_io_size - current.avg_io_size) / max(current.avg_io_size, 1) > thresholds['avg_io_size']:
            return True
        if abs(new_profile.iops - current.iops) / max(current.iops, 1) > thresholds['iops']:
            return True
            
        return False

def main():
    """Main function to run the HPC storage auto-tuner"""
    tuner = HpcStorageTuner()
    
    try:
        tuner.monitor_and_tune(interval=5)
    except KeyboardInterrupt:
        print("Auto-tuner stopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
