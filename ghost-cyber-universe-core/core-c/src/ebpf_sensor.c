#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/*
 * [Persona: Rust Security Engineer / Systems Security Programmer]
 * eBPF-based security monitoring and detection sensors
 */

// Network monitoring maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(max_entries, 1024);
    __uint(key, __be32);
    __uint(value, struct network_stats);
} network_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key, struct connection_key);
    __uint(value, struct connection_info);
} connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_values, __u32);
    __uint(value, struct security_event);
} security_events SEC(".maps");

// Data structures
struct network_stats {
    __u32 packet_count;
    __u32 byte_count;
    __u32 connection_count;
    __u64 last_seen;
};

struct connection_key {
    __u32 src_ip;
    __u32 src_port;
    __u32 dst_ip;
    __u32 dst_port;
    __u8 protocol;
};

struct connection_info {
    __u64 start_time;
    __u32 packet_count;
    __u32 byte_count;
    __u8 flags;
    __u8 state;
};

struct security_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    char description[64];
};

// Event types
#define EVENT_SUSPICIOUS_CONNECTION  1
#define EVENT_PORT_SCAN           2
#define EVENT_DATA_EXFILTRATION   3
#define EVENT_MALICIOUS_PAYLOAD   4
#define EVENT_ANOMALOUS_TRAFFIC  5

// eBPF programs
SEC("socket")
int monitor_network_connections(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    // Only process IP packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    struct connection_key key = {0};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    struct connection_info *info = bpf_map_lookup_elem(&connection_map, &key);
    if (!info) {
        // New connection
        struct connection_info new_info = {0};
        new_info.start_time = bpf_ktime_get_ns();
        new_info.packet_count = 1;
        new_info.byte_count = bpf_ntohs(ip->tot_len);
        new_info.state = 1;  // ESTABLISHED
        
        bpf_map_update_elem(&connection_map, &key, &new_info);
    } else {
        // Existing connection
        info->packet_count++;
        info->byte_count += bpf_ntohs(ip->tot_len);
        
        // Check for suspicious patterns
        if (info->packet_count > 1000) {
            struct security_event event = {0};
            event.timestamp = bpf_ktime_get_ns();
            event.event_type = EVENT_ANOMALOUS_TRAFFIC;
            event.src_ip = ip->saddr;
            event.dst_ip = ip->daddr;
            event.protocol = ip->protocol;
            __builtin_memcpy(event.description, "High packet count", 15);
            
            bpf_perf_event_output(skb, &event, BPF_F_CURRENT_CPU);
        }
        
        bpf_map_update_elem(&connection_map, &key, info);
    }
    
    return 0;
}

SEC("socket")
int detect_port_scans(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    // Only process TCP packets for port scan detection
    if (ip->protocol != IPPROTO_TCP)
        return 0;
    
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return 0;
    
    // Check for SYN packets (port scan indicator)
    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        
        // Count SYN packets from source
        struct network_stats *stats = bpf_map_lookup_elem(&network_stats_map, &src_ip);
        if (!stats) {
            struct network_stats new_stats = {0};
            new_stats.packet_count = 1;
            new_stats.last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&network_stats_map, &src_ip, &new_stats);
        } else {
            stats->packet_count++;
            
            // Port scan detection: many SYN packets to different destinations
            if (stats->packet_count > 50) {
                struct security_event event = {0};
                event.timestamp = bpf_ktime_get_ns();
                event.event_type = EVENT_PORT_SCAN;
                event.src_ip = src_ip;
                event.protocol = IPPROTO_TCP;
                __builtin_memcpy(event.description, "Port scan detected", 18);
                
                bpf_perf_event_output(skb, &event, BPF_F_CURRENT_CPU);
            }
            
            stats->last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&network_stats_map, &src_ip, stats);
        }
    }
    
    return 0;
}

SEC("socket")
int detect_malicious_payloads(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    // Check for common malicious payload patterns
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        
        void *payload = (void *)(tcp + 1);
        int payload_len = data_end - payload;
        
        if (payload_len > 0) {
            // Simple pattern matching for known malicious signatures
            if (bpf_probe_read_user_str(payload, payload_len, "\\x90\\x90\\x90\\x90", 4) == 0) {
                struct security_event event = {0};
                event.timestamp = bpf_ktime_get_ns();
                event.event_type = EVENT_MALICIOUS_PAYLOAD;
                event.src_ip = ip->saddr;
                event.dst_ip = ip->daddr;
                event.protocol = IPPROTO_TCP;
                __builtin_memcpy(event.description, "Shellcode pattern detected", 22);
                
                bpf_perf_event_output(skb, &event, BPF_F_CURRENT_CPU);
            }
            
            // Check for suspicious user agents in HTTP
            if (bpf_probe_read_user_str(payload, payload_len, "sqlmap", 6) == 0 ||
                bpf_probe_read_user_str(payload, payload_len, "nikto", 5) == 0 ||
                bpf_probe_read_user_str(payload, payload_len, "metasploit", 9) == 0) {
                
                struct security_event event = {0};
                event.timestamp = bpf_ktime_get_ns();
                event.event_type = EVENT_SUSPICIOUS_CONNECTION;
                event.src_ip = ip->saddr;
                event.dst_ip = ip->daddr;
                event.protocol = IPPROTO_TCP;
                __builtin_memcpy(event.description, "Hacking tool detected", 19);
                
                bpf_perf_event_output(skb, &event, BPF_F_CURRENT_CPU);
            }
        }
    }
    
    return 0;
}

SEC("socket")
int detect_data_exfiltration(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    // Check for large data transfers (potential exfiltration)
    if (bpf_ntohs(ip->tot_len) > 1000000) {  // > 1MB
        struct connection_key key = {0};
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;
        key.protocol = ip->protocol;
        
        struct connection_info *info = bpf_map_lookup_elem(&connection_map, &key);
        if (info) {
            info->byte_count += bpf_ntohs(ip->tot_len);
            
            // Flag potential exfiltration
            if (info->byte_count > 10000000) {  // > 10MB transferred
                struct security_event event = {0};
                event.timestamp = bpf_ktime_get_ns();
                event.event_type = EVENT_DATA_EXFILTRATION;
                event.src_ip = ip->saddr;
                event.dst_ip = ip->daddr;
                event.protocol = ip->protocol;
                __builtin_memcpy(event.description, "Large data transfer detected", 24);
                
                bpf_perf_event_output(skb, &event, BPF_F_CURRENT_CPU);
            }
            
            bpf_map_update_elem(&connection_map, &key, info);
        }
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";
