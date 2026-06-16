# Network Monitor
### CS250 Assignment 2
### Ailya Zainab, BSDS-2A, 523506

A multi-threaded network monitoring system demonstrating custom stack and queue data structures applied to real-time packet capture, protocol dissection, filtering, and replay.

---

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

# Loopback testing
sudo ./network_monitor lo
```

---

## System Architecture

### Multi-Threaded Pipeline
```
[Capture Thread] → [Capture Queue] → [Filter Thread] → [Replay Queue] → [Replay Thread]
                         ↓                                                      ↓
                  [Dissection Samples]                                  [Backup Queue]
                  (first 5 packets saved                                (retry mechanism,
                   independently for demo)                               up to 2 retries)
```

### Core Components

#### 1. Custom Thread-Safe Queue (`PacketQueue`)
```cpp
class PacketQueue {
    // Thread-safe operations via mutex & condition variables
    void enqueue(const Packet &packet);
    bool dequeueWithTimeout(Packet &output, int timeoutMs);
    bool dequeue(Packet &output);
    int getSize();
};
```
Implemented as a linked-list FIFO. A `mutex` protects all structural modifications; a `condition_variable` allows the consumer thread to block efficiently rather than spin. Unlock-before-notify is used to avoid waking a thread that immediately blocks again on the mutex.

#### 2. Protocol Layer Stack (`LayerStack`)
```cpp
class LayerStack {
    // LIFO structure for protocol layer tracking
    void push(const string &layer);
    bool pop();
    vector<string> toVector(); // Returns layers in bottom-to-top order
};
```
A linked-list stack. Protocol layers are pushed in order of parsing (Ethernet → IP → TCP/UDP); `toVector()` reverses them to present the logical bottom-to-top stack order. LIFO is the natural fit here: the last layer pushed is the first to be unwound when dissection is complete.

#### 3. Packet Structure
```cpp
struct Packet {
    int id;                 // Unique identifier
    string timestamp;       // Capture time (thread-safe via localtime_r)
    uint8_t *rawData;       // Owning pointer — deep copied on assignment
    ssize_t size;
    string sourceIP;
    string destinationIP;
    int replayAttempts;     // Retry counter for backup queue
};
```
Implements a copy constructor and copy-assignment operator to manage the `rawData` heap buffer. The destructor calls `free(rawData)`, following RAII.

---

## Features

### Real-Time Packet Capture
- Raw `AF_PACKET` socket bound to a user-specified interface
- Captures all EtherTypes (Ethernet, IPv4, IPv6)
- 1-second socket receive timeout allows clean shutdown without blocking

### Protocol Dissection (`PacketDissector`)
- Ethernet → IPv4/IPv6 → TCP/UDP, layer by layer
- Bounds-checked at every header boundary; truncated packets are labelled rather than crashed on
- Source/destination IP and port extracted and stored per packet

### IP Filtering (`FilterManager`)
- User-supplied source and/or destination IP filters
- Empty filter string matches any address
- Oversized packets (> 1500 bytes) are counted; after `OVERSIZED_PACKET_LIMIT` total oversized packets, further oversized packets are skipped with a log message

### Replay with Retry (`NetworkReplayer`)
- Filtered packets replayed onto the same interface via a second raw socket
- Failed sends moved to a backup queue
- Up to `MAX_REPLAY_RETRIES` (2) retry attempts per packet; packets exceeding the limit are dropped with a log message
- Per-packet replay delay simulated as `packet_size / 1000` ms

### Dissection Demo
- The first `DISSECTION_SAMPLE_SIZE` (5) packets are saved during capture, independently of the filter/replay pipeline
- Dissection output is printed after shutdown and always has packets to show, regardless of filter settings

---

## Configuration Constants

```cpp
static const int MAX_PACKET_SIZE       = 65536;  // Receive buffer size
static const int REPLAY_SIZE_THRESHOLD = 1500;   // Oversized packet threshold (bytes)
static const int MAX_REPLAY_RETRIES    = 2;       // Retry limit per failed packet
static const int DEMO_RUNTIME_SECONDS  = 60;      // Demo duration
static const int OVERSIZED_PACKET_LIMIT = 10;    // Total oversized packets before skipping
static const int DISSECTION_SAMPLE_SIZE = 5;     // Packets saved for end-of-run demo
```

---

## Data Structure Justification

| Structure | Class | Why |
|---|---|---|
| Linked-list FIFO queue | `PacketQueue` | Packets arrive and are consumed in order; O(1) enqueue and dequeue; no fixed-size limit |
| Linked-list LIFO stack | `LayerStack` | Protocol layers are parsed outermost-first and naturally unwound in reverse; LIFO matches the encapsulation model |

Three queues are used: `captureQueue` (producer: capture thread; consumer: filter thread), `replayQueue` (producer: filter thread; consumer: replay thread), and `backupQueue` (producer/consumer: replay thread for retry handling).

---

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

[Filter] Packet 3 matched filters. Delay=0.090 ms
[Replayer] Packet 3 replayed successfully (size=90)
[Filter] Packet 7 matched filters. Delay=0.054 ms
[Replayer] Packet 7 replayed successfully (size=54)
...
[Demo] 50 seconds remaining...
[Demo] 40 seconds remaining...
...
[Demo] Stopping services...
[Demo] Final Queue Statistics:
[Display] Capture queue size: 0
[Display] Replay queue size: 0
[Display] Backup queue size: 0

[Demo] Dissecting 5 captured packets:
  Packet ID=1 Time=2024-01-15 14:30:22 Size=90 Source=192.168.1.100 Destination=142.250.80.46
    Layers: Ethernet | IPv4 | SourceIPv4:192.168.1.100 | DestinationIPv4:142.250.80.46 | TCP | SourcePort:52341 | DestinationPort:80
  ...
[Demo] Network Monitor demonstration completed successfully
```

---

## Generating Test Traffic

```bash
# ICMP
ping google.com -c 50

# TCP
curl http://example.com

# UDP
nping --udp -p 53 8.8.8.8
```

### Interface Discovery
```bash
ip link show      # List available interfaces
ifconfig          # Traditional listing
```

---

## Thread Safety Notes

- `PacketQueue` uses a `std::mutex` and `std::condition_variable`; all queue operations acquire the lock before touching shared state
- `getCurrentTimestamp()` uses `localtime_r` (POSIX reentrant) rather than `localtime`, which returns a pointer to a static buffer and is not safe to call concurrently from multiple threads
- `CaptureManager::dissectionSamples` is protected by its own `mutex` since it is written by the capture thread and read by `main` after join

---

## Important Notes

Raw socket access requires elevated permissions:
```bash
sudo ./network_monitor
```

Default interface is `eth0`. Alternatives: `wlan0` (Wi-Fi), `lo` (loopback — useful for testing without external traffic).

---

## Repository
https://github.com/Ailya-Shah/StackQueueNetwork-Monitor
