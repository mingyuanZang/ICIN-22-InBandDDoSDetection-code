
control Monitor_Packet(inout headers_t hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {


    action mark_to_monitor(){
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }

    action send_to_cpu(){
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        hdr.packet_in._padding = 0;
    }


    action send_digest(){
        digest<monitor_digest>(1,
            {standard_metadata.ingress_port,
             0,
             hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr,
             hdr.ipv4.protocol,
             hdr.l4_ports.l4_srcPort,
             hdr.l4_ports.l4_dstPort,
             hdr.digest_count.tcp_pkt_num,
             hdr.digest_count.tcp_syn_num,
             hdr.digest_count.tcp_rst_num,
             hdr.digest_count.udp_pkt_num,
             hdr.digest_count.pkt_num,
             hdr.digest_count.unique_port_pairs_num
             });
    }

    table packet_check {
        key = {
            hdr.l4_ports.l4_dstPort: exact;

        }
        actions = {
            mark_to_monitor;
            send_to_cpu;
            send_digest;
            NoAction;
        }
        default_action = NoAction;
    }


    apply {
        if (hdr.ipv4.isValid()) {

            packet_check.apply();
        }
    }
}
