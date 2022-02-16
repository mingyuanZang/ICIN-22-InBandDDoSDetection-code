
#define MAX_STAGE_COUNT 4
#define MAX_PORTS 511
#define MAX_INDEX_INT 4294967295
#define BIT16_INDEX 65535
#define MAX_INDEX_TEST 2147483647

#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1

// for tcp flags
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SA 0x12

// bloom filter
#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;
typedef bit<16> l4_port_t;
typedef bit<6>  l4_flag_t;

typedef bit<32>  pkt_num_count_t;
typedef bit<48> time_t;




const bit<8>  TYPE_ICMP = 0x01;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  TYPE_TCP  = 0x06;
const bit<8>  TYPE_UDP  = 0x11;
const bit<6>  SYN = 2;
const bit<6>  RST = 4;
const bit<4>  BYTE_TO_BIT = 8;
const bit<9>  CPU_PORT = 255;

const bit<16> ETH_LEN = 14;
const bit<16> IPV4_LEN = 20;
const bit<16> UDP_LEN = 8;
const bit<16> KFS_LEN = 13;
const bit<16> MAX_IPV4 = 1480;


const macAddr_t SRC_MAC = 0x010000000001;
const ip4Addr_t SRC_IP = 0xC0A80201;
const l4_port_t UDP_SRC = 1111;

const bit<32> REPORT_MIRROR_SESSION_ID = 500;




// count the number of pkts in window period
register<bit<32>>(MAX_PORTS) pkt_counter;
register<bit<32>>(MAX_PORTS) tcp_pkt_counter;
register<bit<32>>(MAX_PORTS) udp_pkt_counter;
register<bit<32>>(MAX_PORTS) tcp_syn_counter;
register<bit<32>>(MAX_PORTS) tcp_rst_counter;

// bloom filter
register<bit<32>>(MAX_PORTS) unique_port_pairs_counter;
// time counter
register<time_t>(MAX_PORTS) last_time_reg;
register<bit<2>>(1) TIME_FLAG;
