#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parsers.p4"
#include "includes/checksum.p4"
#include "includes/ing_forward.p4"
#include "includes/ing_monitor_packetin.p4"
#include "includes/eg_clone_type.p4"
#include "includes/port_counters.p4"


control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{

    Port_counters_ingress() port_counters_ingress;
    Forward() forward;
    Monitor_Packet() mon_packet;

    // Bloom filter

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;
    bit<32> reg_pos;
    bit<1> reg_val_one;

    // from https://github.com/p4lang/tutorials/blob/master/exercises/firewall/solution/firewall.p4
    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2,  bit<8>protocol){
       //Get register position
       hash(reg_pos, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    apply{

        port_counters_ingress.apply(hdr, standard_metadata);

        // Packet Count
        pkt_counter.read(hdr.digest_count.pkt_num, meta.pkt_num);
        tcp_pkt_counter.read(hdr.digest_count.tcp_pkt_num, meta.tcp_pkt_num);
        udp_pkt_counter.read(hdr.digest_count.udp_pkt_num, meta.udp_pkt_num);
        tcp_syn_counter.read(hdr.digest_count.tcp_syn_num, meta.tcp_syn_num);
        tcp_rst_counter.read(hdr.digest_count.tcp_rst_num, meta.tcp_rst_num);
        // port counter
        unique_port_pairs_counter.read(hdr.digest_count.unique_port_pairs_num, meta.unique_port_pairs_num);

        hdr.digest_count.pkt_num = hdr.digest_count.pkt_num + 1;
        pkt_counter.write(meta.pkt_num, hdr.digest_count.pkt_num);

            if (hdr.tcp.isValid()) {
                compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.l4_ports.l4_srcPort, hdr.l4_ports.l4_dstPort, hdr.ipv4.protocol);
                // bloom filter
                bloom_filter.read(reg_val_one, reg_pos);
                if (reg_val_one != 1){
                    hdr.digest_count.unique_port_pairs_num = hdr.digest_count.unique_port_pairs_num + 1;
                    unique_port_pairs_counter.write(meta.unique_port_pairs_num, hdr.digest_count.unique_port_pairs_num);

                    bloom_filter.write(reg_pos, 1);
                }



                hdr.digest_count.tcp_pkt_num = hdr.digest_count.tcp_pkt_num + 1;
                tcp_pkt_counter.write(meta.tcp_pkt_num, hdr.digest_count.tcp_pkt_num);
                // if (hdr.tcp.ctrl & TCP_FLAG_SYN == SYN) {
                if (hdr.tcp.ctrl == SYN) {
                    hdr.digest_count.tcp_syn_num = hdr.digest_count.tcp_syn_num + 1;
                    tcp_syn_counter.write(meta.tcp_syn_num, hdr.digest_count.tcp_syn_num);
                }
                // if (hdr.tcp.ctrl & TCP_FLAG_RST == RST) {
                if (hdr.tcp.ctrl == RST) {
                    hdr.digest_count.tcp_rst_num = hdr.digest_count.tcp_rst_num + 1;
                    tcp_rst_counter.write(meta.tcp_rst_num, hdr.digest_count.tcp_rst_num);
                }
            }
            if (hdr.udp.isValid()) {
                hdr.digest_count.udp_pkt_num = hdr.digest_count.udp_pkt_num + 1;
                udp_pkt_counter.write(meta.udp_pkt_num, hdr.digest_count.udp_pkt_num);
            }




            // count time
            bit<2> time_flag;
            TIME_FLAG.read(time_flag, 0);
            time_flag = 0;
            TIME_FLAG.write(0, time_flag);


            time_t last_time;
            time_t cur_time = standard_metadata.ingress_global_timestamp;
            time_t delta_time;


            // read / update the last_time_reg
            last_time_reg.read(last_time, (bit<32>)standard_metadata.ingress_port);
            delta_time = cur_time - last_time;


            if (hdr.digest_count.pkt_num > 1){
                if (delta_time > 1000000) {
                    delta_time = 0;
                    last_time_reg.write((bit<32>)standard_metadata.ingress_port, cur_time);
                    time_flag = 2;
                    TIME_FLAG.write(0, time_flag);

                    mon_packet.apply(hdr, meta, standard_metadata);

                    pkt_counter.write(0, 0);
                    tcp_pkt_counter.write(0, 0);
                    udp_pkt_counter.write(0, 0);
                    tcp_syn_counter.write(0, 0);
                    tcp_rst_counter.write(0, 0);
                    bloom_filter.write(0,0);
                    unique_port_pairs_counter.write(0, 0);
                }
            }

            forward.apply(hdr, meta, standard_metadata);



    }
}

control EgressImpl(inout headers_t hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata)
{

    Port_counters_egress() port_counters_egress;
    Clone_Type() clone_type;

    apply{
        port_counters_egress.apply(hdr, standard_metadata);
        bit<2> time_flag;
        TIME_FLAG.read(time_flag, 0);

        if(time_flag == 2){
            clone_type.apply(hdr, meta, standard_metadata);
        }
        time_flag = 0;
        TIME_FLAG.write(0, time_flag);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
