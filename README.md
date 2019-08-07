
This tool allows to get ogg formatted opus file for given RTP.

Examples
========

#### Record opusfile from RTP-stream

In case we have a `in.pcap` that contains the ethernet frames and UDP and RTP encapsulation, we can record audio like the following.

```
tshark -x -r in.pcap -Y "rtp && udp.srcport == myport" | cut -d " " -f 1-20 > tmp.txt
hex_to_opus.py --hexfile tmp.txt --outfile out.opus --udplen 20
```

#### Record opusfile from encrypted RTP-stream

In case we have an encrypted `in.pcap`, we can use the `srtp decrypt` tool to get the `tmp.txt` file. And we can record the opus-audio file like the following.

```
hex_to_opus.py --hexfile tmp.txt --outfile out.opus
```


