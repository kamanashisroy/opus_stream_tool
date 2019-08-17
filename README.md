
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
hex_to_opus.py --hexfile tmp.txt --outfile out.opus --udplen 64 --srtpkey somebase64key
```

It is also possible to filter using `ssrc` and payload type.


```
hex_to_opus.py --hexfile tmp.txt --outfile out.opus --udplen 64 --srtpkey somebase64key --ssrc 1234 --payloadtype 111
```

Requirements
=============

    - Python 3 (TODO make a python2.7 version)
    - pylibsrtp (pip install pylibsrtp)

Links
========

    - similar tools for amr [Codec payload Extractor](https://github.com/Spinlogic/AMR-WB_extractor)
    - [srtp-decrypt](https://github.com/gteissier/srtp-decrypt)
    - [opus-tools](https://opus-codec.org/downloads/)
