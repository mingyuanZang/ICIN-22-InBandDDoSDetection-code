parser ParserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.l4_metadata.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP : parse_icmp;
            TYPE_TCP  : parse_tcp_ports;
            TYPE_UDP  : parse_udp_ports;
            default   : accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp_ports{
        packet.extract(hdr.l4_ports);
        transition parse_tcp;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.kf.l4_flag = hdr.tcp.ctrl;
        transition accept;
    }

    state parse_udp_ports{
        packet.extract(hdr.l4_ports);
        transition parse_udp;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.kf.l4_flag = 0;
        transition accept;
    }
}

control DeparserImpl(packet_out packet,
                     in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.rep_ethernet);
        packet.emit(hdr.rep_ipv4);
        packet.emit(hdr.rep_l4_ports);
        packet.emit(hdr.rep_udp);
        packet.emit(hdr.sum);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.l4_ports);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
