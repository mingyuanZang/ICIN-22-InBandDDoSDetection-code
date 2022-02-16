import socket
import sys
import struct
import os
import IN
from scapy.all import *
import binascii
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
import pandas as pd
from sklearn.preprocessing import OrdinalEncoder
from multiprocessing import Process


model_path = "xgboost.sav"

cols=['curr_time', 'srcAddr', 'dstAddr', 'protocol', 'srcPort', 'dstPort', 'srcPortcnt',  'tcp_pkt_num', 'tcp_syn_num',  'tcp_rst_num', 'udp_pkt_num',  'pkt_num', 'syn_slope']
cols_selected=['tcp_syn_num', 'srcPortcnt', 'syn_slope', 'tcp_rst_num','tcp_pkt_num',  'udp_pkt_num'] # for xgboost

UDP_SERVER_IP = '192.168.2.100'
UDP_SERVER_PORT = 12345
PREDICTION = True
TIME_DURATION = 10
rcv_pkt_stats_df_prev = None
curr_time = None
pkt_counter = 0

InfoDF = pd.DataFrame()



#  stackoverflow.com/a/57395466/2107205
def _timestamp(prec=0):
    t = time.time()
    s = time.strftime("%H:%M:%S", time.localtime(t))
    if prec > 0:
        s += ("%.9f" % (t % 1,))[1:2+prec]
    return s

class mllearning:
    def load_model(self):
        print('Loading model...')
        if model_path:
            model = pickle.load(open(model_path, 'rb'))
            print('Model loaded.')
        else:
            model = None
            print('No model loaded.')
        return model

    def model_predit(self, pkt_stats_df, model):
        pkt_stats_df_origin = pkt_stats_df.copy()

        pkt_stats_df = pkt_stats_df[cols_selected]
        pred = model.predict(pkt_stats_df)
        print('prediction result: ', pred)
        now = _timestamp(prec=6) # microseconds
        print('prediction curr_time', now)
        df_pred = pd.DataFrame(pred,columns=['prediction'])
        pkt_stats_df_pred = df_pred.join(pkt_stats_df_origin)
        print('pkt_stats_df_pred', pkt_stats_df_pred)
        pkt_stats_df_pred.to_csv('pkt_samples_output_labeled.csv', mode='a', index=False, header=True)
        print("parsed packets are labeled and saved to csv. ")
        return pkt_stats_df_pred


def hex_to_ip(rcv_ip_hex):
    rcv_ip_int_list = []
    for i in range(0, len(rcv_ip_hex)):
        rcv_ip_int_list.append(str(int(str(rcv_ip_hex[i]), 16)))
    rcv_ip_formatted  = '.'.join(rcv_ip_int_list)
    return rcv_ip_formatted


# parse src_ip, dst_ip, src_port, dst_port, pkt_len, proto
def parse_rcv_pkt_test1(hexbyte):
    # parse the received packet statistics
    rcv_src_ip_hex = hexbyte[0:4]
    rcv_dst_ip_hex = hexbyte[4:8]
    rcv_src_ip_hex_formatted = hex_to_ip(rcv_src_ip_hex)
    rcv_dst_ip_hex_formatted = hex_to_ip(rcv_dst_ip_hex)
    print('rcv_src_ip_hex_formatted', rcv_src_ip_hex_formatted)
    print('rcv_dst_ip_hex_formatted', rcv_dst_ip_hex_formatted)
    rcv_src_port_hex = ''.join(hexbyte[8:10])
    rcv_dst_port_hex = ''.join(hexbyte[10:12])
    rcv_src_port_hex_formatted = int(str(rcv_src_port_hex), 16)
    rcv_dst_port_hex_formatted = int(str(rcv_dst_port_hex), 16)
    print('rcv_src_port_hex_formatted', rcv_src_port_hex_formatted)
    print('rcv_dst_port_hex_formatted', rcv_dst_port_hex_formatted)
    pktlen = ''.join(hexbyte[12:14])
    ipproto = ''.join(hexbyte[14:15])
    rcv_pktlen_hex_formatted = int(str(pktlen), 16)
    rcv_ipproto_hex_formatted = int(str(ipproto), 16)
    print('rcv_pktlen_hex_formatted', rcv_pktlen_hex_formatted)
    print('rcv_ipproto_hex_formatted', rcv_ipproto_hex_formatted)
    one_pkt_stats = [rcv_src_ip_hex_formatted, rcv_dst_ip_hex_formatted, rcv_src_port_hex_formatted, rcv_dst_port_hex_formatted, rcv_pktlen_hex_formatted, rcv_ipproto_hex_formatted]
    one_pkt_stats_df = pd.DataFrame([one_pkt_stats], columns=cols)
    print('one_pkt_stats_df', one_pkt_stats_df)
    return one_pkt_stats_df


# parse src_ip, dst_ip, proto, src_port, dst_port
def parse_rcv_pkt_test2(hexbyte, curr_time):
    # parse the received packet statistics
    rcv_src_ip_hex = hexbyte[0:4]
    rcv_dst_ip_hex = hexbyte[4:8]
    rcv_src_ip_hex_formatted = hex_to_ip(rcv_src_ip_hex)
    rcv_dst_ip_hex_formatted = hex_to_ip(rcv_dst_ip_hex)
    print('rcv_src_ip_hex_formatted', rcv_src_ip_hex_formatted)
    print('rcv_dst_ip_hex_formatted', rcv_dst_ip_hex_formatted)
    ipproto = ''.join(hexbyte[8:9])
    rcv_ipproto_hex_formatted = int(str(ipproto), 16)
    print('rcv_ipproto_hex_formatted', rcv_ipproto_hex_formatted)
    rcv_src_port_hex = ''.join(hexbyte[9:11])
    rcv_dst_port_hex = ''.join(hexbyte[11:13])
    rcv_src_port_hex_formatted = int(str(rcv_src_port_hex), 16)
    rcv_dst_port_hex_formatted = int(str(rcv_dst_port_hex), 16)
    print('rcv_src_port_hex_formatted', rcv_src_port_hex_formatted)
    print('rcv_dst_port_hex_formatted', rcv_dst_port_hex_formatted)
    rcv_tcp_pkt_num_hex = ''.join(hexbyte[13:17])
    rcv_tcp_syn_num_hex = ''.join(hexbyte[17:21])
    rcv_tcp_rst_num_hex = ''.join(hexbyte[21:25])
    rcv_udp_pkt_num_hex = ''.join(hexbyte[25:29])
    rcv_pkt_num_hex = ''.join(hexbyte[29:33])
    rcv_tcp_pkt_num_hex_formatted = int(str(rcv_tcp_pkt_num_hex), 16)
    rcv_tcp_syn_num_hex_formatted = int(str(rcv_tcp_syn_num_hex), 16)
    rcv_tcp_rst_num_hex_formatted = int(str(rcv_tcp_rst_num_hex), 16)
    rcv_udp_pkt_num_hex_formatted = int(str(rcv_udp_pkt_num_hex), 16)
    rcv_pkt_num_hex_formatted = int(str(rcv_pkt_num_hex), 16)
    print('rcv_tcp_pkt_num_hex_formatted', rcv_tcp_pkt_num_hex_formatted)
    print('rcv_tcp_syn_num_hex_formatted', rcv_tcp_syn_num_hex_formatted)
    print('rcv_tcp_rst_num_hex_formatted', rcv_tcp_rst_num_hex_formatted)
    print('rcv_udp_pkt_num_hex_formatted', rcv_udp_pkt_num_hex_formatted)
    print('rcv_pkt_num_hex_formatted', rcv_pkt_num_hex_formatted)
    syn_slope = rcv_tcp_syn_num_hex_formatted/TIME_DURATION
    rcv_src_portcnt_hex = ''.join(hexbyte[33:37])
    rcv_src_portcnt_hex_formatted = int(str(rcv_src_portcnt_hex), 16)
    print('rcv_src_portcnt_hex_formatted', rcv_src_portcnt_hex_formatted)

    one_pkt_stats = [curr_time, rcv_src_ip_hex_formatted, rcv_dst_ip_hex_formatted, rcv_ipproto_hex_formatted, rcv_src_port_hex_formatted, rcv_dst_port_hex_formatted, rcv_src_portcnt_hex_formatted, rcv_tcp_pkt_num_hex_formatted, rcv_tcp_syn_num_hex_formatted, rcv_tcp_rst_num_hex_formatted, rcv_udp_pkt_num_hex_formatted, rcv_pkt_num_hex_formatted, syn_slope]
    # print('one_pkt_stats', one_pkt_stats)
    one_pkt_stats_df = pd.DataFrame([one_pkt_stats], columns=cols)
    print('one_pkt_stats_df', one_pkt_stats_df)
    # print('type one_pkt_stats_df', type(one_pkt_stats_df))
    return one_pkt_stats_df

class packet_sniffer(Process):
  def __init__(self):
    super(packet_sniffer,self).__init__()
    print("Packet sniffer started")

  def run(self):
      packet = sniff(filter="udp and host 192.168.2.100", prn=self.PacketHandler)

  def PacketHandler(self,packet):
      global pkt_counter
      pkt_counter += 1
      curr_time = _timestamp(prec=6) # microseconds
      print('curr_time', curr_time)
      packet.show()
      print(binascii.hexlify(str(packet[0][UDP].payload)))
      hexbyte = str(binascii.hexlify(str(packet[0][UDP].payload)))
      hexbyte = [hexbyte[i:i+2] for i in range(0, len(hexbyte), 2)]
      print(hexbyte)

      rcv_pkt_stats_df = parse_rcv_pkt_test2(hexbyte, curr_time)

      if PREDICTION == True:
          rcv_pkt_stats_df_prec = learn.model_predit(rcv_pkt_stats_df, model)
          print("parsed packets saved to csv. ")
          # rcv_pkt_stats_df_prec = learn.model_predit(InfoDF, model)
          # InfoDF = pd.DataFrame()
      else:
          rcv_pkt_stats_df.to_csv('pkt_samples_outputm.csv', mode='a', index=False, header=True)
          print("parsed packets saved to csv. ")


if __name__ == "__main__":
    ## udp_server()
    learn = mllearning()
    model = learn.load_model()
    print('model loaded from ', model_path)
    print('model', model)
    ## Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print('sniffing on %s' % iface)
    sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, iface)
    # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    ## Bind the socket to the port
    server_address = (UDP_SERVER_IP, UDP_SERVER_PORT)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)


    print('\nwaiting to receive message...')
    sniffer = packet_sniffer()
    packet = sniffer.run()
