Packet payload xor by nfqueue and userspace program xor which is written by golang. Xor is its own inverse. That is, to undo xor, the same algorithm is applied, so the same action can be used for encoding and decoding.
==================

## requirement
```bash
yum install libnetfilter_queue libnetfilter_queue-devel
```

## iperf udp benchmark
### config
client(192.168.150.20): 
```bash
    iptables -A OUTPUT -d 192.168.150.114/32 -p udp -m udp --dport 8888 -j NFQUEUE --queue-num 1
    ./xor -queue 1 -key abcde
    iperf -u -c 192.168.150.114 -p 8888 -l 50 -b 4M
```

server(192.168.150.114): 
```bash
    iptables -A INPUT -p udp -m udp --dport 8888 -j NFQUEUE --queue-num 1
    ./xor -queue 1 -key abcde
    iperf -u -s -p 8888
```

### result
|duration|drop/total|droprate|
|---|---|---|
|10s|1405/100000|1.4%|
|10s|1193/99999|1.2%|
|10s|1/100000|0.001%|
|10s|1646/100000|1.6%|
|10s|63/99998|0.063%|
