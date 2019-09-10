
This tool allows to record ogg formatted opus file for given RTP pcap.

Examples
========

#### Record opusfile from pcap containing RTP-stream

##### In one step using `pcap_to_opus.py`

TODO

##### In two step using `tshark` and `hex_to_opus.py`.

In case we have a `in.pcap` that contains the ethernet frames and UDP and RTP encapsulation, we can record audio like the following.

```
tshark -x -r in.pcap -Y "udp.srcport == myport" | cut -d " " -f 1-20 > tmp.txt
hex_to_opus.py -x tmp.txt --recordfile out.opus --rtpoffset 42
```

And if the pcap contains ethernet layer and UDP header, then rtpoffset(=42) should contain the length of those headers. 

For encrypted packets, we can specify the srtpkey.

```
hex_to_opus.py -x tmp.txt --recordfile out.opus --rtpoffset 42 --srtpkey somebase64key
```

It is also possible to filter using `ssrc` and payload type.


```
hex_to_opus.py -x tmp.txt --recordfile out.opus --rtpoffset 42 --srtpkey somebase64key --ssrc 1234 --payloadtype 111
```

Requirements
=============

    - Python 3 (TODO make a python2.7 version)
    - pylibsrtp (pip install pylibsrtp)

Links
========

[Codec payload Extractor]:https://github.com/Spinlogic/AMR-WB_extractor
[pylibsrtp]:https://pylibsrtp.readthedocs.io/en/latest/
[srtp-decrypt]:https://github.com/gteissier/srtp-decrypt
[opus-tools]:https://opus-codec.org/downloads/
