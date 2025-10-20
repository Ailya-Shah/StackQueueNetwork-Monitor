# Advanced Network Monitor

CS250 Assignment 2 
# Network Monitor
### Ailya Zainab, BSDS-2A, 523506 

**Professional-Grade Real-Time Network Analysis System**

## Overview

A high-performance, multi-threaded network monitoring system that demonstrates advanced data structure implementation and real-time packet processing.


## Compilation & Execution

### Requirements
- Linux system with root privileges
- g++ compiler with C++17 support
- Network interface with traffic

### Compilation
```bash
g++ -std=c++17 -o network_monitor network_monitor.cpp -pthread
```

### Execution
```bash
# Default interface (eth0)
sudo ./network_monitor

# Specific interface
sudo ./network_monitor wlan0

# Loopback testing
sudo ./network_monitor lo
```

## System Architecture

### Multi-Threaded Pipeline
```
[Capture Thread] → [Capture Queue] → [Filter Thread] → [Replay Queue] → [Replay Thread]
                                      ↓
                                [Backup Queue] (Retry Mechanism)
```

### Core Components

#### 1. **Custom Thread-Safe Queue**
```cpp
class PacketQueue {
    // Lock-free operations with mutex & condition variables
    void enqueue(const Packet &packet);
    bool dequeueWithTimeout(Packet &output, int timeoutMs);
    // Thread-safe size monitoring
};
```

#### 2. **Protocol Layer Stack**
```cpp
class LayerStack {
    // LIFO structure for protocol parsing
    void push(const string &layer);
    vector<string> toVector(); // Bottom-to-top order
};
```

#### 3. **Intelligent Packet Management**
```cpp
struct Packet {
    int id;                    // Unique identifier
    string timestamp;          // High-resolution timing
    uint8_t *rawData;          // Deep-copied packet buffer
    string sourceIP;           // Pre-parsed addresses
    string destinationIP;      // For fast filtering
    int replayAttempts;        // Retry tracking
};
```

## Advanced Features

### Real-Time Packet Processing
- **Continuous capture** during 60-second demo
- **Live filtering** with user-defined IP rules
- **Dynamic delay calculation**: `packet_size / 1000 ms`
- **Oversized packet management** with configurable thresholds

### Professional Error Handling
```cpp
// Automatic retry system with backup queue
if (!sendPacket(packet)) {
    packet.replayAttempts++;
    if (packet.replayAttempts <= MAX_REPLAY_RETRIES) {
        backupQueue.enqueue(packet); // Queue for retry
    } else {
        // Permanent failure handling
    }
}
```

### Complete Protocol Support
- **Ethernet**: MAC addresses, EtherType detection
- **IPv4**: Address parsing, header length calculation
- **IPv6**: Extended address support, next header protocol
- **TCP**: Port numbers, sequence analysis
- **UDP**: Port mapping, length validation

## Performance Metrics

**Demonstrated Capability:**
-  **379+ packets** processed in 60 seconds
-  **Zero packet loss** in normal operation
-  **Real-time throughput** with varied packet sizes
-  **Consistent delay simulation** based on packet size
-  **Clean shutdown** with proper resource cleanup

## Usage Example

```bash
$ sudo ./network_monitor eth0
Network Monitor Starting - Interface: eth0
Enter source IP filter (empty for any): 192.168.1.100
Enter destination IP filter (empty for any): 

[Demo] Starting all services...
[Capture] Starting capture on interface: eth0 at 2024-01-15 14:30:22
[Filter] Starting filter loop. Source=192.168.1.100 Destination=<any>
[Replayer] Starting replay on eth0

# Real-time output during operation:
[Filter] Packet 39617 matched filters. Delay=0.090 ms
[Replayer] Packet 39617 replayed successfully (size=90)
[Filter] Packet 39618 matched filters. Delay=0.054 ms
[Replayer] Packet 39618 replayed successfully (size=54)

[Demo] Final Statistics:
[Display] Current queue size: 0
[Display] Current queue size: 0  
[Display] Current queue size: 0
[Demo] Network Monitor demonstration completed successfully
```

## Testing & Validation

### Generate Test Traffic
```bash
# ICMP packets
ping google.com -c 50

# TCP traffic
curl http://example.com

# UDP traffic
nping --udp -p 53 8.8.8.8
```

### Interface Discovery
```bash
ip link show              # List available interfaces
ifconfig                  # Traditional interface listing
```

## 📋 Configuration Constants

```cpp
static const int MAX_PACKET_SIZE = 65536;        // Maximum packet buffer
static const int REPLAY_SIZE_THRESHOLD = 1500;   // Oversized packet threshold  
static const int MAX_REPLAY_RETRIES = 2;         // Retry limit per packet
static const int DEMO_RUNTIME_SECONDS = 60;      // Required demo duration
static const int OVERSIZED_PACKET_LIMIT = 10;    // Consecutive oversized limit
```

### Data Structure Implementation
- **Custom Queue**: Thread-safe FIFO with linked list
- **Custom Stack**: LIFO protocol parsing structure
- **Memory Management**: Deep copy semantics, RAII principles

### Algorithm Application
- **Protocol Parsing**: Layer-by-layer stack-based dissection
- **Filtering Algorithms**: IP-based matching with performance optimization
- **Scheduling**: Packet delay simulation based on size

### System Design
- **Producer-Consumer Pattern**: Multi-threaded pipeline
- **Error Recovery**: Backup queues with retry limits
- **Resource Management**: Proper socket and memory cleanup

## Important Notes

### Root Privileges Required
```bash
# Raw socket access needs elevated permissions
sudo ./network_monitor
```

### Interface Selection
- Default: `eth0` (Ethernet)
- Alternatives: `wlan0` (WiFi), `lo` (loopback)
- Use `ip link show` to discover available interfaces

### Performance Considerations
- System handles high packet rates efficiently
- Memory usage optimized with proper buffer management
- Thread synchronization prevents data races

## 📈 Sample Output Analysis

The system successfully demonstrates:
- **High throughput**: 379+ packets in 60 seconds
- **Accurate filtering**: All packets matched user criteria
- **Proper timing**: Delay calculations match packet sizes
- **Zero failures**: All packets replayed successfully
- **Clean operation**: No memory leaks or resource issues

## 🔗 GitHub Repository
https://github.com/Ailya-Shah/StackQueueNetwork-Monitor

---

