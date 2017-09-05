Packet payload xor by nfqueue and program xor which is written by C.  
[Xor](https://en.wikipedia.org/wiki/XOR_cipher) is its own inverse. That is, to undo xor, the same algorithm is applied, so the same action can be used for encoding and decoding.
==========

## with checksum
### Test1
* kernel 2.6.32
* (c)E5-2620 0, i350 -> (s)R720xd, E5-2630 0, BCM5720
* iperf single thread

1. iperf udp test
|duration|drop|drop_rate|bw|
|---|---|---|---|
|10s|1131/690989|(0.16%)|27.6Mbps|
|10s|6001/690338|(0.87%)|27.4Mbps|
|10s|76932/691593|(11%)|24.6Mbps|
|10s|45321/690953|(6.6%)|25.8Mbps|

2. iperf tcp bw test
449Mbps 357Mbps 367Mbps 349Mbps 328Mbps 381Mbps 387Mbps

### Test2
* kernel 4.1.0
* (c)E5-2640 0, virtio -> (s) E3-1230 V2, i350
* iperf single thread

1. iperf udp test
duration drop drop_rate
10s 22736/1300000 (1.7%) 51.1Mbps

2. iperf tcp bw test
580Mbps 592Mbps 566Mbps
