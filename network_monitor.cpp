// network_monitor.cpp
// CS250 Assignment 2 - Network Monitor
// Custom Stack and Queue implementations for network packet analysis
// Raw socket capture with dissection of Ethernet, IPv4, IPv6, TCP, UDP
// Filtering and replay with backup + up to 2 retries
// 60-second demonstration run

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <algorithm>  // Added for reverse function
#include <ctime>
#include <mutex>
#include <condition_variable>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <errno.h>

using namespace std;

// -------------------------------
// Configuration Constants
// -------------------------------
static const int MAX_PACKET_SIZE = 65536;
static const int REPLAY_SIZE_THRESHOLD = 1500;
static const int MAX_REPLAY_RETRIES = 2;
static const int DEMO_RUNTIME_SECONDS = 60;
static const int OVERSIZED_PACKET_LIMIT = 10;

// -------------------------------
// Utility Functions
// -------------------------------
string getCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&time));
    return string(buffer);
}

string convertIPv4ToString(uint32_t address) {
    struct in_addr addr;
    addr.s_addr = address;
    return string(inet_ntoa(addr));
}

string convertIPv6ToString(const struct in6_addr &address) {
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &address, buffer, sizeof(buffer));
    return string(buffer);
}

// -------------------------------
// Packet Structure
// -------------------------------
struct Packet {
    int id;
    string timestamp;
    uint8_t *rawData;
    ssize_t size;
    string sourceIP;
    string destinationIP;
    int replayAttempts;

    Packet() : id(0), timestamp(), rawData(nullptr), size(0), 
               sourceIP(), destinationIP(), replayAttempts(0) {}
    
    // Deep copy constructor
    Packet(const Packet &other) {
        id = other.id;
        timestamp = other.timestamp;
        size = other.size;
        sourceIP = other.sourceIP;
        destinationIP = other.destinationIP;
        replayAttempts = other.replayAttempts;
        
        if (size > 0 && other.rawData) {
            rawData = (uint8_t*)malloc(size);
            memcpy(rawData, other.rawData, size);
        } else {
            rawData = nullptr;
        }
    }
    
    Packet& operator=(const Packet &other) {
        if (this == &other) return *this;
        
        if (rawData) free(rawData);
        
        id = other.id;
        timestamp = other.timestamp;
        size = other.size;
        sourceIP = other.sourceIP;
        destinationIP = other.destinationIP;
        replayAttempts = other.replayAttempts;
        
        if (size > 0 && other.rawData) {
            rawData = (uint8_t*)malloc(size);
            memcpy(rawData, other.rawData, size);
        } else {
            rawData = nullptr;
        }
        return *this;
    }
    
    ~Packet() {
        if (rawData) free(rawData);
    }
};

// -------------------------------
// Custom Queue Implementation (Thread-Safe)
// -------------------------------
class PacketQueue {
private:
    struct Node {
        Packet packet;
        Node* next;
        Node(const Packet &pkt) : packet(pkt), next(nullptr) {}
    };
    
    Node* head;
    Node* tail;
    int elementCount;
    mutex queueMutex;
    condition_variable conditionVar;

public:
    PacketQueue() : head(nullptr), tail(nullptr), elementCount(0) {}
    
    ~PacketQueue() {
        clear();
    }

    void enqueue(const Packet &packet) {
        Node* newNode = new Node(packet);
        unique_lock<mutex> lock(queueMutex);
        
        if (!tail) {
            head = tail = newNode;
        } else {
            tail->next = newNode;
            tail = newNode;
        }
        
        ++elementCount;
        lock.unlock();
        conditionVar.notify_one();
    }

    bool dequeue(Packet &output) {
        unique_lock<mutex> lock(queueMutex);
        if (!head) return false;
        
        Node* nodeToRemove = head;
        output = nodeToRemove->packet;
        head = head->next;
        
        if (!head) tail = nullptr;
        
        --elementCount;
        lock.unlock();
        delete nodeToRemove;
        return true;
    }

    bool dequeueWithTimeout(Packet &output, int timeoutMs) {
        unique_lock<mutex> lock(queueMutex);
        
        if (!conditionVar.wait_for(lock, chrono::milliseconds(timeoutMs), 
                                  [&]{ return head != nullptr; })) {
            return false;
        }
        
        Node* nodeToRemove = head;
        output = nodeToRemove->packet;
        head = head->next;
        
        if (!head) tail = nullptr;
        
        --elementCount;
        lock.unlock();
        delete nodeToRemove;
        return true;
    }

    bool peek(Packet &output) {
        unique_lock<mutex> lock(queueMutex);
        if (!head) return false;
        
        output = head->packet;
        return true;
    }

    int getSize() {
        unique_lock<mutex> lock(queueMutex);
        return elementCount;
    }

    void clear() {
        unique_lock<mutex> lock(queueMutex);
        while (head) {
            Node* temp = head;
            head = head->next;
            delete temp;
        }
        tail = nullptr;
        elementCount = 0;
    }
};

// -------------------------------
// Custom Stack Implementation for Protocol Layers
// -------------------------------
class LayerStack {
private:
    struct Node {
        string layerName;
        Node* next;
        Node(const string &layer) : layerName(layer), next(nullptr) {}
    };
    
    Node* topNode;

public:
    LayerStack() : topNode(nullptr) {}
    
    ~LayerStack() {
        while (topNode) {
            Node* temp = topNode;
            topNode = topNode->next;
            delete temp;
        }
    }
    
    void push(const string &layer) {
        Node* newNode = new Node(layer);
        newNode->next = topNode;
        topNode = newNode;
    }
    
    bool pop() {
        if (!topNode) return false;
        
        Node* temp = topNode;
        topNode = topNode->next;
        delete temp;
        return true;
    }
    
    string getTop() {
        return topNode ? topNode->layerName : string();
    }
    
    bool isEmpty() {
        return topNode == nullptr;
    }

    vector<string> toVector() const {
        vector<string> layers;
        Node* current = topNode;
        
        while (current) {
            layers.push_back(current->layerName);
            current = current->next;
        }
        
        // Reverse to get bottom-to-top order
        reverse(layers.begin(), layers.end());
        return layers;
    }
};

// -------------------------------
// Packet Dissector
// -------------------------------
class PacketDissector {
public:
    static void dissect(const Packet &packet, LayerStack &stack, vector<string> &outputLayers) {
        if (packet.size <= 0 || packet.rawData == nullptr) return;
        
        // Parse Ethernet layer
        if (packet.size < (ssize_t)sizeof(ether_header)) {
            outputLayers.push_back("Truncated/Ethernet");
            return;
        }
        
        stack.push("Ethernet");
        outputLayers.push_back("Ethernet");
        
        const ether_header *ethernetHeader = reinterpret_cast<const ether_header*>(packet.rawData);
        uint16_t etherType = ntohs(ethernetHeader->ether_type);
        size_t currentOffset = sizeof(ether_header);

        // Parse IPv6 packets
        if (etherType == ETHERTYPE_IPV6) {
            if (packet.size < (ssize_t)(currentOffset + sizeof(struct ip6_hdr))) {
                outputLayers.push_back("Truncated/IPv6");
                return;
            }
            
            stack.push("IPv6");
            outputLayers.push_back("IPv6");
            
            const struct ip6_hdr *ipv6Header = reinterpret_cast<const struct ip6_hdr*>(
                packet.rawData + currentOffset);
            currentOffset += sizeof(struct ip6_hdr);
            
            outputLayers.push_back("SourceIPv6:" + convertIPv6ToString(ipv6Header->ip6_src));
            outputLayers.push_back("DestinationIPv6:" + convertIPv6ToString(ipv6Header->ip6_dst));
            
            int nextHeader = ipv6Header->ip6_nxt;
            if (nextHeader == IPPROTO_TCP) {
                parseTCP(packet, currentOffset, stack, outputLayers);
            } else if (nextHeader == IPPROTO_UDP) {
                parseUDP(packet, currentOffset, stack, outputLayers);
            }
        }
        // Parse IPv4 packets
        else if (etherType == ETHERTYPE_IP) {
            if (packet.size < (ssize_t)(currentOffset + sizeof(struct ip))) {
                outputLayers.push_back("Truncated/IPv4");
                return;
            }
            
            stack.push("IPv4");
            outputLayers.push_back("IPv4");
            
            const struct ip *ipv4Header = reinterpret_cast<const struct ip*>(
                packet.rawData + currentOffset);
            int ipHeaderLength = ipv4Header->ip_hl * 4;
            int protocol = ipv4Header->ip_p;
            
            if (packet.size < (ssize_t)(currentOffset + ipHeaderLength)) {
                outputLayers.push_back("Truncated/IPv4-header");
                return;
            }
            
            outputLayers.push_back("SourceIPv4:" + convertIPv4ToString(ipv4Header->ip_src.s_addr));
            outputLayers.push_back("DestinationIPv4:" + convertIPv4ToString(ipv4Header->ip_dst.s_addr));
            
            currentOffset += ipHeaderLength;
            
            if (protocol == IPPROTO_TCP) {
                parseTCP(packet, currentOffset, stack, outputLayers);
            } else if (protocol == IPPROTO_UDP) {
                parseUDP(packet, currentOffset, stack, outputLayers);
            }
        } else {
            outputLayers.push_back("UnknownEthertype:" + to_string(etherType));
        }
    }

private:
    static void parseTCP(const Packet &packet, size_t offset, LayerStack &stack, vector<string> &outputLayers) {
        if (packet.size >= (ssize_t)(offset + sizeof(struct tcphdr))) {
            stack.push("TCP");
            outputLayers.push_back("TCP");
            
            const struct tcphdr *tcpHeader = reinterpret_cast<const struct tcphdr*>(
                packet.rawData + offset);
            
            outputLayers.push_back("SourcePort:" + to_string(ntohs(tcpHeader->th_sport)));
            outputLayers.push_back("DestinationPort:" + to_string(ntohs(tcpHeader->th_dport)));
        } else {
            outputLayers.push_back("Truncated/TCP");
        }
    }

    static void parseUDP(const Packet &packet, size_t offset, LayerStack &stack, vector<string> &outputLayers) {
        if (packet.size >= (ssize_t)(offset + sizeof(struct udphdr))) {
            stack.push("UDP");
            outputLayers.push_back("UDP");
            
            const struct udphdr *udpHeader = reinterpret_cast<const struct udphdr*>(
                packet.rawData + offset);
            
            outputLayers.push_back("SourcePort:" + to_string(ntohs(udpHeader->uh_sport)));
            outputLayers.push_back("DestinationPort:" + to_string(ntohs(udpHeader->uh_dport)));
        } else {
            outputLayers.push_back("Truncated/UDP");
        }
    }
};

// -------------------------------
// Packet Capture Manager
// -------------------------------
class CaptureManager {
private:
    int socketDescriptor;
    string networkInterface;
    atomic<bool> isRunning;
    PacketQueue &packetQueue;
    atomic<int> packetIdCounter;
    thread captureThread;

public:
    CaptureManager(PacketQueue &queue, const string &interface) 
        : socketDescriptor(-1), networkInterface(interface), isRunning(false), 
          packetQueue(queue), packetIdCounter(1) {}

    bool initializeSocket() {
        socketDescriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (socketDescriptor < 0) {
            cerr << "[Capture] Failed to create raw socket: " << strerror(errno) << endl;
            return false;
        }
        
        // Bind to specified network interface
        struct sockaddr_ll socketAddress;
        memset(&socketAddress, 0, sizeof(socketAddress));
        socketAddress.sll_family = AF_PACKET;
        socketAddress.sll_ifindex = if_nametoindex(networkInterface.c_str());
        
        if (socketAddress.sll_ifindex == 0) {
            cerr << "[Capture] Interface not found: " << networkInterface << endl;
            close(socketDescriptor);
            return false;
        }
        
        socketAddress.sll_protocol = htons(ETH_P_ALL);
        
        if (bind(socketDescriptor, (struct sockaddr*)&socketAddress, sizeof(socketAddress)) < 0) {
            cerr << "[Capture] Bind failed: " << strerror(errno) << endl;
            close(socketDescriptor);
            return false;
        }

        // Set receive timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        return true;
    }

    void startCapture() {
        isRunning = true;
        captureThread = thread([this](){ this->captureLoop(); });
    }
    
    void stopCapture() {
        isRunning = false;
        if (socketDescriptor >= 0) close(socketDescriptor);
        if (captureThread.joinable()) captureThread.join();
    }

private:
    void captureLoop() {
        cout << "[Capture] Starting capture on interface: " << networkInterface 
             << " at " << getCurrentTimestamp() << endl;
        
        uint8_t *buffer = (uint8_t*)malloc(MAX_PACKET_SIZE);
        
        while (isRunning) {
            ssize_t packetLength = recvfrom(socketDescriptor, buffer, MAX_PACKET_SIZE, 0, nullptr, nullptr);
            
            if (packetLength < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
                    continue; // Timeout or signal, check running status
                }
                cerr << "[Capture] Receive error: " << strerror(errno) << endl;
                break;
            }
            
            // Create and store packet
            Packet newPacket;
            newPacket.id = packetIdCounter++;
            newPacket.timestamp = getCurrentTimestamp();
            newPacket.size = packetLength;
            newPacket.rawData = (uint8_t*)malloc(packetLength);
            memcpy(newPacket.rawData, buffer, packetLength);
            newPacket.replayAttempts = 0;

            extractIPAddresses(newPacket);
            packetQueue.enqueue(newPacket);
            
            this_thread::sleep_for(chrono::milliseconds(1));
        }
        
        free(buffer);
        cout << "[Capture] Capture loop terminated" << endl;
    }

    void extractIPAddresses(Packet &packet) {
        if (packet.size < (ssize_t)sizeof(ether_header)) return;
        
        const ether_header *ethernetHeader = reinterpret_cast<const ether_header*>(packet.rawData);
        uint16_t etherType = ntohs(ethernetHeader->ether_type);
        size_t offset = sizeof(ether_header);
        
        if (etherType == ETHERTYPE_IP && packet.size >= (ssize_t)(offset + sizeof(struct ip))) {
            const struct ip *ipv4Header = reinterpret_cast<const struct ip*>(packet.rawData + offset);
            packet.sourceIP = convertIPv4ToString(ipv4Header->ip_src.s_addr);
            packet.destinationIP = convertIPv4ToString(ipv4Header->ip_dst.s_addr);
        } else if (etherType == ETHERTYPE_IPV6 && packet.size >= (ssize_t)(offset + sizeof(struct ip6_hdr))) {
            const struct ip6_hdr *ipv6Header = reinterpret_cast<const struct ip6_hdr*>(packet.rawData + offset);
            packet.sourceIP = convertIPv6ToString(ipv6Header->ip6_src);
            packet.destinationIP = convertIPv6ToString(ipv6Header->ip6_dst);
        }
    }
};

// -------------------------------
// Network Replayer
// -------------------------------
class NetworkReplayer {
private:
    PacketQueue &replayQueue;
    PacketQueue &backupQueue;
    string networkInterface;
    atomic<bool> isRunning;
    int outputSocket;
    thread replayThread;

public:
    NetworkReplayer(PacketQueue &replayQ, PacketQueue &backupQ, const string &interface)
        : replayQueue(replayQ), backupQueue(backupQ), networkInterface(interface), 
          isRunning(false), outputSocket(-1) {}

    bool initializeOutputSocket() {
        outputSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (outputSocket < 0) {
            cerr << "[Replayer] Failed to create output socket: " << strerror(errno) << endl;
            return false;
        }
        
        struct sockaddr_ll socketAddress;
        memset(&socketAddress, 0, sizeof(socketAddress));
        socketAddress.sll_family = AF_PACKET;
        socketAddress.sll_ifindex = if_nametoindex(networkInterface.c_str());
        
        if (socketAddress.sll_ifindex == 0) {
            cerr << "[Replayer] Interface not found: " << networkInterface << endl;
            close(outputSocket);
            return false;
        }
        
        socketAddress.sll_protocol = htons(ETH_P_ALL);
        
        if (bind(outputSocket, (struct sockaddr*)&socketAddress, sizeof(socketAddress)) < 0) {
            cerr << "[Replayer] Bind failed: " << strerror(errno) << endl;
            close(outputSocket);
            return false;
        }
        
        return true;
    }

    void startReplay() {
        isRunning = true;
        replayThread = thread([this](){ this->replayLoop(); });
    }
    
    void stopReplay() {
        isRunning = false;
        if (outputSocket >= 0) close(outputSocket);
        if (replayThread.joinable()) replayThread.join();
    }

private:
    void replayLoop() {
        cout << "[Replayer] Starting replay on " << networkInterface << endl;
        
        while (isRunning) {
            Packet packet;
            if (!replayQueue.dequeueWithTimeout(packet, 500)) {
                continue;
            }
            
            bool sentSuccessfully = sendPacket(packet);
            
            if (!sentSuccessfully) {
                packet.replayAttempts++;
                backupQueue.enqueue(packet);
                cout << "[Replayer] Packet " << packet.id << " moved to backup (attempt " 
                     << packet.replayAttempts << ")" << endl;
            } else {
                cout << "[Replayer] Packet " << packet.id << " replayed successfully (size=" 
                     << packet.size << ")" << endl;
            }

            // Simulate network delay based on packet size
            int delayMs = max(1, (int)(packet.size / 1000));
            this_thread::sleep_for(chrono::milliseconds(delayMs));

            processBackupQueue();
        }
        
        cout << "[Replayer] Replay loop terminated" << endl;
    }

    bool sendPacket(const Packet &packet) {
        if (outputSocket < 0) return false;
        
        struct sockaddr_ll destination;
        memset(&destination, 0, sizeof(destination));
        destination.sll_family = AF_PACKET;
        destination.sll_ifindex = if_nametoindex(networkInterface.c_str());
        destination.sll_halen = ETH_ALEN;
        
        ssize_t bytesSent = sendto(outputSocket, packet.rawData, packet.size, 0, 
                                 (struct sockaddr*)&destination, sizeof(destination));
        
        if (bytesSent < 0) {
            cerr << "[Replayer] Send failed for packet " << packet.id << ": " 
                 << strerror(errno) << endl;
            return false;
        }
        
        return bytesSent == packet.size;
    }

    void processBackupQueue() {
        Packet backupPacket;
        if (backupQueue.dequeue(backupPacket)) {
            if (backupPacket.replayAttempts <= MAX_REPLAY_RETRIES) {
                bool retrySuccess = sendPacket(backupPacket);
                
                if (!retrySuccess) {
                    backupPacket.replayAttempts++;
                    
                    if (backupPacket.replayAttempts > MAX_REPLAY_RETRIES) {
                        cout << "[Replayer] Packet " << backupPacket.id 
                             << " exceeded maximum retries, dropping" << endl;
                    } else {
                        backupQueue.enqueue(backupPacket);
                        cout << "[Replayer] Retry queued for Packet " << backupPacket.id 
                             << " (attempt " << backupPacket.replayAttempts << ")" << endl;
                    }
                } else {
                    cout << "[Replayer] Backup Packet " << backupPacket.id 
                         << " replayed successfully on retry" << endl;
                }
            }
        }
    }
};

// -------------------------------
// Filter Manager
// -------------------------------
class FilterManager {
private:
    PacketQueue &captureQueue;
    PacketQueue &replayQueue;
    atomic<bool> isRunning;
    string sourceFilter;
    string destinationFilter;
    int oversizedPacketCount;
    int oversizedPacketLimit;
    thread filterThread;

public:
    FilterManager(PacketQueue &captureQ, PacketQueue &replayQ)
        : captureQueue(captureQ), replayQueue(replayQ), isRunning(false), 
          oversizedPacketCount(0), oversizedPacketLimit(OVERSIZED_PACKET_LIMIT) {}

    void setFilters(const string &source, const string &destination) {
        sourceFilter = source;
        destinationFilter = destination;
    }

    void startFiltering() {
        isRunning = true;
        filterThread = thread([this](){ this->filterLoop(); });
    }
    
    void stopFiltering() {
        isRunning = false;
        if (filterThread.joinable()) filterThread.join();
    }

private:
    void filterLoop() {
        cout << "[Filter] Starting filter loop. Source=" 
             << (sourceFilter.empty() ? "<any>" : sourceFilter)
             << " Destination=" << (destinationFilter.empty() ? "<any>" : destinationFilter) << endl;
        
        while (isRunning) {
            Packet packet;
            if (!captureQueue.dequeueWithTimeout(packet, 200)) {
                continue;
            }
            
            if (packet.size > REPLAY_SIZE_THRESHOLD) {
                oversizedPacketCount++;
                if (oversizedPacketCount > oversizedPacketLimit) {
                    cout << "[Filter] Skipping oversized packet " << packet.id 
                         << " (size=" << packet.size << ")" << endl;
                    continue;
                }
            }
            
            if (matchesFilter(packet)) {
                replayQueue.enqueue(packet);
                double delay = (double)packet.size / 1000.0;
                cout << "[Filter] Packet " << packet.id << " matched filters. Delay=" 
                     << fixed << setprecision(3) << delay << " ms" << endl;
            }
            
            this_thread::sleep_for(chrono::milliseconds(1));
        }
        
        cout << "[Filter] Filter loop terminated" << endl;
    }

    bool matchesFilter(const Packet &packet) {
        bool sourceMatch = sourceFilter.empty() || packet.sourceIP == sourceFilter;
        bool destinationMatch = destinationFilter.empty() || packet.destinationIP == destinationFilter;
        return sourceMatch && destinationMatch;
    }
};

// -------------------------------
// Display Functions
// -------------------------------
void displayQueueStatus(PacketQueue &queue) {
    cout << "[Display] Current queue size: " << queue.getSize() << endl;
}

void demonstratePacketDissection(PacketQueue &queue, int maxPackets) {
    cout << "[Demo] Dissecting " << maxPackets << " packets:" << endl;
    
    for (int i = 0; i < maxPackets; i++) {
        Packet packet;
        if (!queue.dequeue(packet)) break;
        
        cout << "Packet ID=" << packet.id << " Time=" << packet.timestamp 
             << " Size=" << packet.size << " Source=" << packet.sourceIP 
             << " Destination=" << packet.destinationIP << endl;
        
        LayerStack layerStack;
        vector<string> layers;
        PacketDissector::dissect(packet, layerStack, layers);
        
        cout << "  Layers: ";
        for (auto &layer : layers) {
            cout << layer << " | ";
        }
        cout << endl;
    }
}

// -------------------------------
// Main Application
// -------------------------------
int main(int argc, char** argv) {
    // Verify root privileges
    if (geteuid() != 0) {
        cerr << "Error: This program requires root privileges. Use: sudo ./network_monitor" << endl;
        return 1;
    }
    
    string networkInterface = (argc > 1) ? string(argv[1]) : "eth0";
    cout << "Network Monitor Starting - Interface: " << networkInterface << endl;

    // Initialize queues
    PacketQueue captureQueue;
    PacketQueue replayQueue;
    PacketQueue backupQueue;

    // Initialize capture manager
    CaptureManager captureManager(captureQueue, networkInterface);
    if (!captureManager.initializeSocket()) {
        cerr << "Failed to initialize capture on " << networkInterface << endl;
        return 1;
    }

    // Initialize replayer
    NetworkReplayer networkReplayer(replayQueue, backupQueue, networkInterface);
    if (!networkReplayer.initializeOutputSocket()) {
        cerr << "Failed to initialize replayer on " << networkInterface << endl;
        return 1;
    }

    // Initialize filter manager
    FilterManager filterManager(captureQueue, replayQueue);
    
    // Get filter criteria from user
    string sourceFilter, destinationFilter;
    cout << "Enter source IP filter (empty for any): ";
    getline(cin, sourceFilter);
    cout << "Enter destination IP filter (empty for any): ";
    getline(cin, destinationFilter);
    
    filterManager.setFilters(sourceFilter, destinationFilter);

    // Start all services
    cout << "[Demo] Starting all services..." << endl;
    captureManager.startCapture();
    filterManager.startFiltering();
    networkReplayer.startReplay();

    // Run demonstration for required 60 seconds
    cout << "[Demo] Running for " << DEMO_RUNTIME_SECONDS << " seconds..." << endl;
    for (int i = 0; i < DEMO_RUNTIME_SECONDS; i++) {
        this_thread::sleep_for(chrono::seconds(1));
        if (i % 10 == 0) {
            cout << "[Demo] " << (DEMO_RUNTIME_SECONDS - i) << " seconds remaining..." << endl;
        }
    }

    // Stop all services
    cout << "[Demo] Stopping services..." << endl;
    captureManager.stopCapture();
    filterManager.stopFiltering();
    networkReplayer.stopReplay();

    // Display results
    cout << "[Demo] Final Statistics:" << endl;
    displayQueueStatus(captureQueue);
    displayQueueStatus(replayQueue);
    displayQueueStatus(backupQueue);

    // Demonstrate packet dissection
    demonstratePacketDissection(captureQueue, 5);

    cout << "[Demo] Network Monitor demonstration completed successfully" << endl;
    return 0;
}