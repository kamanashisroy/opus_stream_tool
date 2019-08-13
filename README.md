
This tool allows to get ogg formatted opus file for given RTP.

Examples
========

#### Record opusfile from pcap containing RTP-stream

##### In one step using `pcap_to_opus.py`

TODO

##### In two step using `tshark` and `hex_to_opus.py`.

In case we have a `in.pcap` that contains the ethernet frames and UDP and RTP encapsulation, we can record audio like the following.

```
tshark -x -r in.pcap -Y "rtp && udp.srcport == myport" | cut -d " " -f 1-20 > tmp.txt
hex_to_opus.py --hexfile tmp.txt --outfile out.opus --udplen 20
```

Note the UDP header length is 20 for ipv4. And if the pcap contains ethernet layer, then udplen(=42) should contain all the other layers as well. In case of IPv4 it becomes 64. udplen does not mean udpheder length, but the offset of rtp header.

For encrypted packets, we can specify the srtpkey.

```
hex_to_opus.py --hexfile tmp.txt --outfile out.opus --udplen 64 --srtpkey somebase64key=
```



