#!/usr/bin/python

'''
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import argparse
import struct
import sys
import math
import matplotlib
import matplotlib.pyplot as pyplot
import datetime
from collections import namedtuple
from hex_to_opus import RTP_HEADER,RTP_HEADER_FMT


__all__ = ['rtp_plot']
__author__ = "Kamanashis Roy"
__copyright__ = "Copyright (C) 2019 Kamanashis Roy"
__license__ = "GNU Public License version 3"
__version__ = "1.0"

class rtp_plot_stream:
    def __init__(self,ssrc):
        self.timeline = []
        self.rtp_sequence = []
        self.ssrc = ssrc

    def append(self, rtp_sequence, tm):
        self.timeline.append(tm)
        self.rtp_sequence.append(rtp_sequence)

RTP_FIXED_HEADER = 12
COLOR_LIST = ['red','green','blue','black','silver','orange']
class rtp_plot:
    '''
    Plot rtp
    '''
    def __init__(self, rtp_offset = 0, verbose=False, payload_type=None, filter_ssrc=None):
        self.rtp_offset = rtp_offset
        self.payload_type = payload_type
        self.filter_ssrc = filter_ssrc
        self.verbose = verbose
        self.streams = {}


    def process_rtp_packet(self, packet, tm):
        if not packet:
            print("No packet")
            return False

        rtp_raw_full = None
        try:
            rtp_raw_full = bytes.fromhex(''.join(packet[self.rtp_offset:]))
        except:
            print("Failed to get hex", packet)
            return False

        if len(rtp_raw_full) < RTP_FIXED_HEADER:
            print("udp payload is too small")
            return False

        # decode RTP Header
        rtp_raw_header = rtp_raw_full[:RTP_FIXED_HEADER]

        if self.verbose:
            print(rtp_raw_header.hex())
        rtp = RTP_HEADER._make(struct.unpack(RTP_HEADER_FMT, rtp_raw_header))
        if self.verbose:
            print(rtp)

        # Filter the RTP with v=2
        if (rtp.FIRST & 0b11000000) != 0b10000000:
            print("Not an RTP")
            return False

        # Filter opus
        if self.payload_type and rtp.PAYLOAD_TYPE != self.payload_type:
            print("Skipping payload {rtp_payload_type} while {opus_payload_type} expected.".format(rtp_payload_type=rtp.PAYLOAD_TYPE, opus_payload_type=self.payload_type))
            return False

        if self.filter_ssrc and self.filter_ssrc != rtp.SSRC:
            print("Skipping ssrc={rtp_ssrc} while {filter_ssrc} expected".format(rtp_ssrc=rtp.SSRC,filter_ssrc=self.filter_ssrc))
            return False

        if rtp.SSRC not in self.streams:
            self.streams[rtp.SSRC] = rtp_plot_stream(rtp.SSRC)
        strm = self.streams[rtp.SSRC]
        strm.append(rtp.SEQUENCE_NUMBER, tm)

    def save_file(self, filename):
        # configure x-axis
        ax = pyplot.gca()
        ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%Y-%m-%d %H:%M:%S.%f"))
        ax.xaxis.set_tick_params(rotation=30, labelsize=10)
        pyplot.xlabel('Timeline')
        pyplot.ylabel('Sequence')

        col = iter(COLOR_LIST)
        for unused,strm in self.streams.items():
            pyplot.plot_date(strm.timeline, strm.rtp_sequence, xdate=True, ydate=False, markersize=5, linewidth=2, color=next(col,'yellow'))
        pyplot.savefig(filename)


    def read_file(self, infile):
        with open(infile, 'r') as rtp_fd:
            packet_counter = 0
            success_counter = 0
            packet = []
            for xline in rtp_fd:
                if ' ' not in xline or not xline:
                    if packet:
                        packet_counter += 1
                        if self.record_rtp_packet(packet):
                            success_counter += 1
                        packet = []
                else:
                    content = xline.split()
                    #print(len(content))
                    content.pop(0) # skip the segment column
                    packet.extend(content)

            if packet:
                self.process_rtp_packet(packet,is_last=True)

            print("Written %d out of %d packets" % (success_counter, packet_counter))
 

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='plot rtp media')
    parser.add_argument('-v'
        , action='store_true'
        , help='Show verbose output')
    parser.add_argument('--hexfile'
        , required=False
        , help='Text output of pcap, hint `tshark -x -r file.pcap -Y "rtp && udp.srcport == myport" | cut -d " " -f 1-20 > strm_from_myport.txt` ')
    parser.add_argument('--outfile'
        , required=False
        , help='Output plot file')
    parser.add_argument('--rtpoffset'
        , required=False
        , type=int
        , default=0
        , help='Offset of rtp header')
    parser.add_argument('--ssrc'
        , required=False
        , type=int
        , default=None
        , help='Specify ssrc as it appears in SDP. It is used to filter-out specific stream')
    parser.add_argument('--payloadtype'
        , required=False
        , type=int
        , default=111
        , help='Specify payload type as it appears in SDP. It is used to filter-out RTCP packets')
 
    args = parser.parse_args()
    if args.v:
        print(args)
    if args.hexfile and args.outfile:
        plotfile = rtp_plot(rtp_offset=args.rtpoffset,verbose=args.v,payload_type=args.payloadtype,filter_ssrc=args.ssrc)
        plotfile.read_file(args.hexfile)
        plotfile.save_file(args.outfile)

