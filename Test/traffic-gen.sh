#!/bin/bash

tcpProc=0
run_tcp_client(){
    rightNow=`date +"%Y_%m_%d_%H_%M_%S"`
    DESTINATION=$1
    TCP_PAYLOAD=$2
    TIME=$3
    RATE=$4
    PORT=$5

    #iperf -c $DESTINATION -p 12345 -l $TCP_PAYLOAD -b $RATE -t $TIME >> /tmp/tcp_client_${rightNow}.txt 2>&1 &
    iperf3 -c $DESTINATION -p $PORT -l $TCP_PAYLOAD -b $RATE -t $TIME >> /tmp/tcp_client_${rightNow}.txt 2>&1 &
    tcpProc=$!
}

udpProc=0
run_udp_client(){
    rightNow=`date +"%Y_%m_%d_%H_%M_%S"`
    DESTINATION=$1
    UDP_PAYLOAD=$2
    TIME=$3
    RATE=$4
    PORT=$5

    #iperf -c $DESTINATION -u -p 54321 -m $UDP_PAYLOAD -b $RATE -t $TIME >> /tmp/udp_client_${rightNow}.txt 2>&1 &
    iperf3 -c $DESTINATION -u -p $PORT -l $UDP_PAYLOAD -b $RATE -t $TIME >> /tmp/udp_client_${rightNow}.txt 2>&1 &
    udpProc=$!
}


POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -t|--test_time)
    TEST_TIME="$2"
    shift # past argument
    shift # past value
    ;;
    -a|--rate_ratio)
    RATE_RATIO="$2"
    shift # past argument
    shift # past value
    ;;
    -b|--size_ratio)
    SIZE_RATIO="$2"
    shift # past argument
    shift # past value
    ;;
    -r|--packet_ratio)
    PACKET_RATIO="$2"
    shift # past argument
    shift # past value
    ;;
    -s|--send_ip)
    SEND_IP="$2"
    shift # past argument
    shift # past value
    ;;
    -c|--capture_intf)
    CAPTURE_INTF="$2"
    shift # past argument
    shift # past value
    ;;
    --default)
    DEFAULT=YES
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

echo "TEST_TIME      = ${TEST_TIME}"
echo "RATE_RATIO     = ${RATE_RATIO}"
echo "SIZE_RATIO     = ${SIZE_RATIO}"
echo "PACKET_RATIO   = ${PACKET_RATIO}"
echo "SEND_IP        = ${SEND_IP}"
echo "CAPTURE_INTF   = ${CAPTURE_INTF}"

startTime=`date +%s`
rightNow=`date +"%Y_%m_%d_%H_%M_%S"`

TCP_SERVER_P1=11111
TCP_SERVER_P2=11112

UDP_SERVER_P1=22221
UDP_SERVER_P2=22222
UDP_SERVER_P3=22223


#nohup iperf -s -u -p 12345 >> /tmp/udp_server_${rightNow}.txt 2>&1 &
#nohup iperf -s -p 65432 >> /tmp/tcp_server_${rightNow}.txt 2>&1 &
#tcpdump & -s 0 -i $CAPTURE_INTF -y capture_${rightNow}.pcap


MAX_UDP_CLIENTS=3
MAX_TCP_CLIENTS=2

declare -A UDP_CLIENTS
declare -A TCP_CLIENTS

SERVERS=()

TCP_CLIENTS["$TCP_SERVER_P1"]="0"
TCP_CLIENTS["$TCP_SERVER_P2"]="0"

UDP_CLIENTS["$UDP_SERVER_P1"]="0"
UDP_CLIENTS["$UDP_SERVER_P2"]="0"
UDP_CLIENTS["$UDP_SERVER_P3"]="0"

for port in ${!UDP_CLIENTS[@]}; do
    nohup iperf3 -s -p ${port} >> /tmp/udp_server_${rightNow}.txt 2>&1 &
    PID=$!
    echo -e "UDP Server running at PID: $PID \n"
    SERVERS+=($PID)
done

for port in ${!TCP_CLIENTS[@]}; do
    nohup iperf3 -s -p ${port} >> /tmp/tcp_server_${rightNow}.txt 2>&1 &
    PID=$!
    echo -e "TCP Server running at PID: $PID \n"
    SERVERS+=($PID)
done


nohup timeout $TEST_TIME tcpdump -i $CAPTURE_INTF -w capture_${rightNow}.pcap &
echo -e "tcpdump running at PID: $! \n"


while [[ $SECONDS -lt $TEST_TIME ]]
do

    tcpCounter=0
    udpCounter=0
    for port in "${!TCP_CLIENTS[@]}"; do if [[ "${TCP_CLIENTS[${port}]}" == "0" ]]; then ((tcpCounter++)); fi done
    for port in "${!UDP_CLIENTS[@]}"; do if [[ "${UDP_CLIENTS[${port}]}" == "0" ]]; then ((udpCounter++)); fi done

    #echo "TCPC before launching: $tcpCounter"
    #echo "UDPC before launching: $udpCounter"
    
    while [[ $udpCounter -ne 0 ]]
    do
        for port in ${!UDP_CLIENTS[@]}; do
            if [[ "${UDP_CLIENTS[${port}]}" == "0" ]]; then

                pSize=`shuf -i 8-25 -n 1`
                flowTime=`shuf -i 1-5 -n 1`
                rate=`shuf -i 20-80 -n 1`

                run_udp_client "localhost" "$pSize" "$flowTime" "${rate}"k "$port"
                UDP_CLIENTS["$port"]=$udpProc
                ((udpCounter--))
                echo -e "Running UDP process -> Packet size: $pSize, Time for flow: $flowTime, Rate: $rate, PID: $udpProc \n"
            fi
        done
        
        
        sleep `shuf -i 1-3 -n 1` 
        #UDP_CLIENTS[${#UDP_CLIENTS[@]}]=$PID
        #howManyUdpClients=${#UDP_CLIENTS[@]} 
    done

    while [[ $tcpCounter -ne 0 ]]
    do
        for port in ${!TCP_CLIENTS[@]}; do
            if [[ "${TCP_CLIENTS[${port}]}" == "0" ]]; then
                pSize=`shuf -i 200-600 -n 1`
                flowTime=`shuf -i 1-10 -n 1`
                rate=`shuf -i 1-20 -n 1`
                run_tcp_client "localhost" "$pSize" "$flowTime" "${rate}"m "$port"
                TCP_CLIENTS["$port"]=$tcpProc
                ((tcpCounter--))
                echo -e "Running TCP process -> Packet size: $pSize, Time for flow: $flowTime, Rate: $rate, PID: $tcpProc \n"
            fi
        done
       
        sleep `shuf -i 1-3 -n 1`
        #TCP_CLIENTS[${#TCP_CLIENTS[@]}]=$PID
        #howManyTcpClients=${#TCP_CLIENTS[@]}         
    done

    echo "Checking for UDP or TCP processes to finish..."
    tcpRunCounter=0
    udpRunCounter=0
    for port in "${!TCP_CLIENTS[@]}"; do if [[ "${TCP_CLIENTS[${port}]}" != "0" ]]; then ((tcpRunCounter++)); fi done
    for port in "${!UDP_CLIENTS[@]}"; do if [[ "${UDP_CLIENTS[${port}]}" != "0" ]]; then ((udpRunCounter++)); fi done

    #echo "TCPC before enter: $tcpRunCounter"
    #echo "UDPC before enter: $udpRunCounter"

    while [[ $tcpRunCounter -eq MAX_TCP_CLIENTS && $udpRunCounter -eq MAX_UDP_CLIENTS ]]
    do
        echo "TCPC: $tcpRunCounter"
        echo "UDPC: $udpRunCounter"

        for port in ${!UDP_CLIENTS[@]}; do
            echo "Checking: ${UDP_CLIENTS[${port}]}"
            if [[ ${UDP_CLIENTS[${port}]} -ne 0 ]]; then
                UDP_PROC=$(ps -p "${UDP_CLIENTS[${port}]}" | wc -l)
                if [[ $UDP_PROC -eq 1 ]]; then
                    ((udpRunCounter--))
                    echo "One UDP process (${UDP_CLIENTS[${port}]}) for port $port finished and removed. Free servers: $udpRunCounter"
                    UDP_CLIENTS["$port"]=0

                fi
            fi
        done

        for port in ${!TCP_CLIENTS[@]}; do
            echo "Checking: ${TCP_CLIENTS[${port}]}"
            if [[ ${TCP_CLIENTS[${port}]} -ne 0 ]]; then
                TCP_PROC=$(ps -p "${TCP_CLIENTS[${port}]}" | wc -l)
                if [[ $TCP_PROC -eq 1 ]]; then
                    ((tcpRunCounter--))
                    echo "One TCP process (${TCP_CLIENTS[${port}]}) for port $port finished and removed. Free servers: $tcpRunCounter"
                    TCP_CLIENTS["$port"]=0
                fi
            fi
        done

        #echo "TCPC: $tcpRunCounter"
        #echo "UDPC: $udpRunCounter"


        #DEL_UDP_CLIENTS=()
        #for onePid in "${UDP_CLIENTS[@]}"
        #do
        #    UDP_PROC=$(ps -p "$onePid" | wc -l)
        #    if [[ $UDP_PROC -eq 1 ]]; then
        #        #DEL_UDP_CLIENTS[${#DEL_UDP_CLIENTS[@]}]=$onePid
        #    fi
        #done

        #Deleting UDP client procs
        #for del in ${DEL_UDP_CLIENTS[@]}
        #do
        #    UDP_CLIENTS=("${UDP_CLIENTS[@]/$del}") #Quotes when working with strings
        #    echo "One UDP process (${del}) finished and removed. Array size is ${#UDP_CLIENTS[@]}"
        #done'

        # DEL_TCP_CLIENTS=()
        # for onePid in "${TCP_CLIENTS[@]}"
        # do
        #     TCP_PROC=$(ps -p "$onePid" | wc -l)
        #     if [[ $TCP_PROC -eq 1 ]]; then
        #         #DEL_TCP_CLIENTS[${#DEL_TCP_CLIENTS[@]}]=$onePid
        #     fi
        # done

        # #Deleting TCP client procs
        # for del in ${DEL_TCP_CLIENTS[@]}
        # do
        #     TCP_CLIENTS=("${TCP_CLIENTS[@]/$del}") #Quotes when working with strings
        #     echo "One TCP process (${del}) finished and removed. Array size is ${#TCP_CLIENTS[@]}"
        # done


        echo "Waiting ..."
        sleep 1

    done
   
done



for pid in "${SERVERS[@]}"
do
    echo "Killing process $pid ... "
    sudo kill -9 $pid
done
