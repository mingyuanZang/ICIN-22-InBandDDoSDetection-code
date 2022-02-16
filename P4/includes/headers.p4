
// packet in
@controller_header("packet_in")
header packet_in_header_t {
    bit<9>  ingress_port;
    bit<7>  _padding;
}



// packet out
@controller_header("packet_out")
header packet_out_header_t {
    bit<9>  egress_port;
    bit<7>  _padding;
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    // Diffserv -> DSCP + ECN
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t{
    bit<8> tp;
    bit<8> code;
    bit<16> chk;
    bit<16> id;
    bit<16> seqNum;
}

header l4_ports_t {
    l4_port_t   l4_srcPort;
    l4_port_t   l4_dstPort;
}

header tcp_t {
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset; // how long the TCP header is
    bit<3>  res;
    bit<3>  ecn;        //Explicit congestion notification
    bit<6>  ctrl;       // URG,ACK,PSH,RST,SYN,FIN
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> len;
    bit<16> checksum;
}

header field_sum_t{
    ip4Addr_t l3_srcAddr;
    ip4Addr_t l3_dstAddr;
    bit<8>    l3_proto;
    l4_port_t l4_srcPort;
    l4_port_t l4_dstPort;
    pkt_num_count_t      tcp_pkt_num;
    pkt_num_count_t      tcp_syn_num;
    pkt_num_count_t      tcp_rst_num;
    pkt_num_count_t      udp_pkt_num;
    pkt_num_count_t      pkt_num;
    pkt_num_count_t      unique_port_pairs_num; // bloom filter

}


struct monitor_digest {
    egressSpec_t inPort;     // 9 bits-/
    bit<7>       pad;        // 7 bits-/ 2 bytes
    ip4Addr_t    l3_srcAddr; // 4 bytes
    ip4Addr_t    l3_dstAddr; // 4 bytes
    bit<8>       l3_proto;   // 1 byte
    l4_port_t    l4_srcPort; // 2 bytes
    l4_port_t    l4_dstPort; // 2 bytes
    pkt_num_count_t      tcp_pkt_num;
    pkt_num_count_t      tcp_syn_num;
    pkt_num_count_t      tcp_rst_num;
    pkt_num_count_t      udp_pkt_num;
    pkt_num_count_t      pkt_num;
    pkt_num_count_t      unique_port_pairs_num; // bloom filter

}

struct key_fields_t {
    l4_flag_t l4_flag;
}

header digest_count_t {
    pkt_num_count_t      tcp_pkt_num;
    pkt_num_count_t      tcp_syn_num;
    pkt_num_count_t      tcp_rst_num;
    pkt_num_count_t      udp_pkt_num;
    pkt_num_count_t      pkt_num;
    pkt_num_count_t      unique_port_pairs_num; // bloom filter
}



struct clone_type_t {
    bool is_digest;
    bool is_clone;
    bool is_summary;
    bool is_packetio;
}

struct l4_metadata_t {
	bit<16> tcpLength;            // length of tcp header
}

struct metadata {
    key_fields_t kf;
    clone_type_t ct;
    pkt_num_count_t      tcp_pkt_num;
    pkt_num_count_t      tcp_syn_num;
    pkt_num_count_t      tcp_rst_num;
    pkt_num_count_t      udp_pkt_num;
    pkt_num_count_t      pkt_num;
    pkt_num_count_t      unique_port_pairs_num; // bloom filter
    l4_metadata_t        l4_metadata;


}

struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          rep_ethernet;
    ipv4_t              rep_ipv4;
    l4_ports_t          rep_l4_ports;
    udp_t               rep_udp;
    field_sum_t         sum;
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    icmp_t              icmp;
    l4_ports_t          l4_ports;
    tcp_t               tcp;
    udp_t               udp;
    digest_count_t      digest_count;

}
