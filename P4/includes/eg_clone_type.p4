
control Clone_Type(inout headers_t hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {



    action clone_packet(macAddr_t mac,
                        ip4Addr_t ip,
                        l4_port_t udp_port){
        hdr.rep_ethernet.setValid();
        hdr.rep_ipv4.setValid();
        hdr.rep_l4_ports.setValid();
        hdr.rep_udp.setValid();

        hdr.rep_ethernet.srcAddr = SRC_MAC;
        hdr.rep_ethernet.dstAddr = mac;
        hdr.rep_ethernet.etherType = TYPE_IPV4;

        hdr.rep_ipv4.version = 4;
        hdr.rep_ipv4.ihl = 5;
        hdr.rep_ipv4.dscp = 0;
        hdr.rep_ipv4.ecn = 0;
        hdr.rep_ipv4.identification = 0;
        hdr.rep_ipv4.flags = 0;
        hdr.rep_ipv4.fragOffset = 0;
        hdr.rep_ipv4.ttl = 0xFF;
        hdr.rep_ipv4.protocol = TYPE_UDP;
        hdr.rep_ipv4.srcAddr = SRC_IP;
        hdr.rep_ipv4.dstAddr = ip;

        hdr.rep_l4_ports.l4_srcPort = UDP_SRC;
        hdr.rep_l4_ports.l4_dstPort = udp_port;


        // hdr.rep_ipv4.hdrChecksum = 0;
        // hdr.rep_udp.checksum = 0;

        hdr.rep_udp.len =
            UDP_LEN +
            ETH_LEN + //original packet ethernet
            hdr.ipv4.totalLen;

        hdr.rep_ipv4.totalLen =
            hdr.rep_udp.len +
            IPV4_LEN;
    }


    action key_field_summary(macAddr_t mac,
                             ip4Addr_t ip,
                             l4_port_t udp_port){

        clone_packet(mac, ip, udp_port);

        hdr.sum.setValid();
        hdr.sum.l3_srcAddr = hdr.ipv4.srcAddr;
        hdr.sum.l3_dstAddr = hdr.ipv4.dstAddr;
        hdr.sum.l3_proto = hdr.ipv4.protocol;
        hdr.sum.l4_srcPort = hdr.l4_ports.l4_srcPort;
        hdr.sum.l4_dstPort = hdr.l4_ports.l4_dstPort;
        hdr.sum.tcp_pkt_num = hdr.digest_count.tcp_pkt_num;
        hdr.sum.tcp_syn_num = hdr.digest_count.tcp_syn_num;
        hdr.sum.tcp_rst_num = hdr.digest_count.tcp_rst_num;
        hdr.sum.udp_pkt_num = hdr.digest_count.udp_pkt_num;
        hdr.sum.pkt_num = hdr.digest_count.pkt_num;
        hdr.sum.unique_port_pairs_num = hdr.digest_count.unique_port_pairs_num;

        hdr.rep_udp.len = hdr.rep_udp.len + KFS_LEN;
        hdr.rep_ipv4.totalLen = hdr.rep_ipv4.totalLen + KFS_LEN;
    }


    table clone_type_tb {
        key = {
            hdr.l4_ports.l4_dstPort: exact;
        }
        actions = {
            clone_packet;
            key_field_summary;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        if(hdr.tcp.isValid()){
            meta.kf.l4_flag = hdr.tcp.ctrl;
        }else{
            meta.kf.l4_flag = 0;
        }

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {

            /* send to ML */
            clone_type_tb.apply();

        }


        if(hdr.rep_ipv4.isValid() && meta.ct.is_summary){
            if(hdr.rep_ipv4.totalLen >= MAX_IPV4){
                hdr.ethernet.setInvalid();
                hdr.ipv4.setInvalid();
                hdr.udp.setInvalid();

                hdr.rep_ipv4.totalLen =
                    hdr.rep_ipv4.totalLen-ETH_LEN-IPV4_LEN-UDP_LEN;

                hdr.rep_udp.len =
                    hdr.rep_udp.len-ETH_LEN-IPV4_LEN-UDP_LEN;
            }
        }
    }
}
