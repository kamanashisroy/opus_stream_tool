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
import base64
from pylibsrtp import Policy,Session
from collections import namedtuple

__all__ = ['ogg_opus_coder','srtp_ogg_opus_coder','ogg_page_coder']
__author__ = "Kamanashis Roy"
__copyright__ = "Copyright (C) 2019 Kamanashis Roy"
__license__ = "GNU Public License version 3"
__version__ = "1.0"

OGG_PAGE_HEADER = namedtuple("OGG_PAGE_HEADER","PATTERN,VERSION,HEADER_TYPE,GRANULE_POS,BITSTREAM,PAGE_SEQ,CRC,NUM_SEGMENTS")
OGG_PAGE_HEADER_FMT = '<4sBBqIIIB'

class ogg_page_coder:
    '''
    https://tools.ietf.org/html/rfc3533

    TODO support bigger packet than 255 bytes
    TODO get the page_seq from the rtp-header
    '''
    def __init__(self, verbose=False, simulate=True):
        self.strm_fd = None
        self.reset()
        self.verbose = verbose
        self.simulate = simulate
        self.curr_bitstream = 0

    def get_curr_bitstream(self):
        return self.curr_bitstream

    def set_curr_bitstream(self, bitstream):
        self.curr_bitstream = bitstream

    def __bool__(self):
        return self.strm_fd is not None;

    def reset(self, strm_fd = None):
        if self.strm_fd:
            self.strm_fd.close()
        self.page_seq = 0
        self.strm_fd = strm_fd

    def _make_page_header(self, content_len, ptime, is_data, is_first, is_last, crc):
        '''
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1| Byte
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | capture_pattern: Magic number for page start "OggS"           | 0-3
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | version       | header_type   | granule_position              | 4-7
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               | 8-11
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               | bitstream_serial_number       | 12-15
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               | page_sequence_number          | 16-19
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               | CRC_checksum                  | 20-23
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               |page_segments  | segment_table | 24-27
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | ...                                                           | 28-
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        We support only one segment now.
        '''
        header_type_flag = 0
        granule_position = 0
        if is_first:
            header_type_flag |= 0x02
        if is_last:
            header_type_flag |= 0x04
        if is_data:
            #header_type_flag |= 0x01
            assert self.page_seq > 1
            granule_position = (self.page_seq-1)*960

        num_segments = content_len >> 8
        if content_len & 0xFF:
            num_segments += 1
        header = OGG_PAGE_HEADER(b'OggS', 0, header_type_flag, granule_position, self.curr_bitstream, self.page_seq, crc, num_segments)

        if self.verbose:
            print("dumping ogg page", header, content_len)

        page_head = []
        # write 27 byte header
        page_head.append(struct.pack(OGG_PAGE_HEADER_FMT, *header))

        # write the segments
        for x in range(num_segments-1):
            page_head.append(struct.pack('<B', 255))

        # write last segment
        if num_segments > 0:
            page_head.append(struct.pack('<B', content_len%255))
            
        page_head = b''.join(page_head)

        assert len(page_head) == (27+num_segments) # header_size = number_page_segments + 27 [Byte]

        return page_head

    def _crc32(self, content, crc=0):
        crc_lookup=[
         0x00000000,0x04c11db7,0x09823b6e,0x0d4326d9,0x130476dc,0x17c56b6b,0x1a864db2,0x1e475005,
         0x2608edb8,0x22c9f00f,0x2f8ad6d6,0x2b4bcb61,0x350c9b64,0x31cd86d3,0x3c8ea00a,0x384fbdbd,
         0x4c11db70,0x48d0c6c7,0x4593e01e,0x4152fda9,0x5f15adac,0x5bd4b01b,0x569796c2,0x52568b75,
         0x6a1936c8,0x6ed82b7f,0x639b0da6,0x675a1011,0x791d4014,0x7ddc5da3,0x709f7b7a,0x745e66cd,
         0x9823b6e0,0x9ce2ab57,0x91a18d8e,0x95609039,0x8b27c03c,0x8fe6dd8b,0x82a5fb52,0x8664e6e5,
         0xbe2b5b58,0xbaea46ef,0xb7a96036,0xb3687d81,0xad2f2d84,0xa9ee3033,0xa4ad16ea,0xa06c0b5d,
         0xd4326d90,0xd0f37027,0xddb056fe,0xd9714b49,0xc7361b4c,0xc3f706fb,0xceb42022,0xca753d95,
         0xf23a8028,0xf6fb9d9f,0xfbb8bb46,0xff79a6f1,0xe13ef6f4,0xe5ffeb43,0xe8bccd9a,0xec7dd02d,
         0x34867077,0x30476dc0,0x3d044b19,0x39c556ae,0x278206ab,0x23431b1c,0x2e003dc5,0x2ac12072,
         0x128e9dcf,0x164f8078,0x1b0ca6a1,0x1fcdbb16,0x018aeb13,0x054bf6a4,0x0808d07d,0x0cc9cdca,
         0x7897ab07,0x7c56b6b0,0x71159069,0x75d48dde,0x6b93dddb,0x6f52c06c,0x6211e6b5,0x66d0fb02,
         0x5e9f46bf,0x5a5e5b08,0x571d7dd1,0x53dc6066,0x4d9b3063,0x495a2dd4,0x44190b0d,0x40d816ba,
         0xaca5c697,0xa864db20,0xa527fdf9,0xa1e6e04e,0xbfa1b04b,0xbb60adfc,0xb6238b25,0xb2e29692,
         0x8aad2b2f,0x8e6c3698,0x832f1041,0x87ee0df6,0x99a95df3,0x9d684044,0x902b669d,0x94ea7b2a,
         0xe0b41de7,0xe4750050,0xe9362689,0xedf73b3e,0xf3b06b3b,0xf771768c,0xfa325055,0xfef34de2,
         0xc6bcf05f,0xc27dede8,0xcf3ecb31,0xcbffd686,0xd5b88683,0xd1799b34,0xdc3abded,0xd8fba05a,
         0x690ce0ee,0x6dcdfd59,0x608edb80,0x644fc637,0x7a089632,0x7ec98b85,0x738aad5c,0x774bb0eb,
         0x4f040d56,0x4bc510e1,0x46863638,0x42472b8f,0x5c007b8a,0x58c1663d,0x558240e4,0x51435d53,
         0x251d3b9e,0x21dc2629,0x2c9f00f0,0x285e1d47,0x36194d42,0x32d850f5,0x3f9b762c,0x3b5a6b9b,
         0x0315d626,0x07d4cb91,0x0a97ed48,0x0e56f0ff,0x1011a0fa,0x14d0bd4d,0x19939b94,0x1d528623,
         0xf12f560e,0xf5ee4bb9,0xf8ad6d60,0xfc6c70d7,0xe22b20d2,0xe6ea3d65,0xeba91bbc,0xef68060b,
         0xd727bbb6,0xd3e6a601,0xdea580d8,0xda649d6f,0xc423cd6a,0xc0e2d0dd,0xcda1f604,0xc960ebb3,
         0xbd3e8d7e,0xb9ff90c9,0xb4bcb610,0xb07daba7,0xae3afba2,0xaafbe615,0xa7b8c0cc,0xa379dd7b,
         0x9b3660c6,0x9ff77d71,0x92b45ba8,0x9675461f,0x8832161a,0x8cf30bad,0x81b02d74,0x857130c3,
         0x5d8a9099,0x594b8d2e,0x5408abf7,0x50c9b640,0x4e8ee645,0x4a4ffbf2,0x470cdd2b,0x43cdc09c,
         0x7b827d21,0x7f436096,0x7200464f,0x76c15bf8,0x68860bfd,0x6c47164a,0x61043093,0x65c52d24,
         0x119b4be9,0x155a565e,0x18197087,0x1cd86d30,0x029f3d35,0x065e2082,0x0b1d065b,0x0fdc1bec,
         0x3793a651,0x3352bbe6,0x3e119d3f,0x3ad08088,0x2497d08d,0x2056cd3a,0x2d15ebe3,0x29d4f654,
         0xc5a92679,0xc1683bce,0xcc2b1d17,0xc8ea00a0,0xd6ad50a5,0xd26c4d12,0xdf2f6bcb,0xdbee767c,
         0xe3a1cbc1,0xe760d676,0xea23f0af,0xeee2ed18,0xf0a5bd1d,0xf464a0aa,0xf9278673,0xfde69bc4,
         0x89b8fd09,0x8d79e0be,0x803ac667,0x84fbdbd0,0x9abc8bd5,0x9e7d9662,0x933eb0bb,0x97ffad0c,
         0xafb010b1,0xab710d06,0xa6322bdf,0xa2f33668,0xbcb4666d,0xb8757bda,0xb5365d03,0xb1f740b4]


        for x in content:
            crc = (crc<<8)^crc_lookup[((crc>>24)&0xFF)^x]
        return crc & 0xffffffff


    def write_page(self, content, ptime=20, is_data=False, is_first=False, is_last=False, pageno=0):
        '''

        '''
        if not self.simulate:
            self.page_seq = pageno

        # get head while crc=0
        head = self._make_page_header(content_len=len(content), ptime=ptime,is_data=is_data,is_first=is_first,is_last=is_last,crc=0)

        # calculate crc
        crc = self._crc32(head)
        crc = self._crc32(content,crc)

        # put correct crc
        head = self._make_page_header(content_len=len(content), ptime=ptime,is_data=is_data,is_first=is_first,is_last=is_last,crc=crc)

        self.strm_fd.write(head)
        self.strm_fd.write(content)

        self.page_seq += 1


    def close(self):
        self.reset()

    def __iter__(self):
        '''
        Allow read all the pages as iterator.
        
        for header,content in ogg_page_coder:
            print(header)

        '''
        if self.strm_fd:
            return self
        else:
            return None

    def next(self): # support for python2
        return __next__

    def __next__(self):
        '''
        Read the page from file
        '''
        if not self.strm_fd:
            raise StopIteration

        page_head_raw = self.strm_fd.read(27)
        if page_head_raw == '':
            raise StopIteration # end of file

        page_head = OGG_PAGE_HEADER._make(struct.unpack(OGG_PAGE_HEADER_FMT, page_head_raw))

        if page_head.NUM_SEGMENTS == 0:
            # empty segment
            print("Error empty segement ", page_head)
            raise StopIteration

        page_segments = None
        if page_head.NUM_SEGMENTS > 0:
            page_segments = self.strm_fd.read(page_head.NUM_SEGMENTS)

        content_len = 0
        content = None
        for x in page_segments:
            content_len += x

        print("read content_len %d" % content_len)
        if content_len:
            content = self.strm_fd.read(content_len)
        return page_head,content

OPUS_IDENTITY_HEADER = namedtuple("OPUS_IDENTITY_HEADER","PATTERN,VERSION,NUM_CHANNELS,PRE_SKIP,SAMPLING_RATE,GAIN,FAMILY")
OPUS_IDENTITY_HEADER_FMT = '<8sBBHIhB'

RTP_HEADER = namedtuple('RTP_HEADER', 'FIRST,PAYLOAD_TYPE,SEQUENCE_NUMBER,TIMESTAMP,SSRC')
RTP_HEADER_FMT = '>BBHII'

class ogg_opus_coder:
    '''
    https://tools.ietf.org/html/rfc7845
    '''
    def __init__(self, pre_skip=11971,sampling_rate=48000,gain=0,verbose=False):
        self.pre_skip = pre_skip
        self.sampling_rate = sampling_rate
        self.gain = gain
        self.verbose = verbose
        self.ogg = ogg_page_coder(verbose)

    def reset(self):
        self.ogg.reset()

    def write_stream_comment(self, vendor, comment = []):
        if self.ogg is None:
            print("No output file")
            return

        comment_content = []

        # OpusTags
        comment_content.append(struct.pack('<8s',b'OpusTags'))

        # add vendor name
        comment_content.append(struct.pack('<I',len(vendor)))
        comment_content.append(vendor.encode("utf-8"))

        # add other comments
        comment_content.append(struct.pack('<I',len(comment)))
        for x in comment:
            comment_content.append(struct.pack('<I',len(x)))
            comment_content.append(x.encode("utf-8"))

        self.ogg.write_page(b''.join(comment_content), ptime=0)

    def write_stream_header(self, bitstream_serial):
        '''
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |      'O'      |      'p'      |      'u'      |      's'      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |      'H'      |      'e'      |      'a'      |      'd'      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |  Version = 1  | Channel Count |           Pre-skip            |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                     Input Sample Rate (Hz)                    |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Output Gain (Q7.8 in dB)    | Mapping Family|               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               :
         |                                                               |
         :               Optional Channel Mapping Table...               :
         |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        '''
        if self.ogg is None:
            print("No output file")
            return
        
        self.ogg.set_curr_bitstream(bitstream_serial)
        # Identification header
        header = OPUS_IDENTITY_HEADER(b'OpusHead', 1, 1, self.pre_skip, self.sampling_rate, self.gain, 0) # version 1, channel 1, pre-skip, freq 48kHz, gain 8, mono = 0
        content = struct.pack(OPUS_IDENTITY_HEADER_FMT, *header)
        self.ogg.write_page(content, is_first=True, ptime=0) 

        # When the 'channel mapping family' octet has this value, the channel mapping table MUST be omitted from the ID header packet.
        #self.ogg.write(struct.pack('<BBB',1,1,1)) # number of stream = 1, coupled streams = 1, channel mapping = 1

    def start_file(self, outfile):
        '''
        Write ogg file
        '''
        self.ogg.reset(open(outfile, 'wb'))

    def end_file(self):
        self.ogg.reset()

    def explain_file(self, infile):
        '''
        Read an ogg file and dump the pages
        '''
        self.ogg.reset(open(infile, 'rb'))

        page_counter = 0
        for header,content in self.ogg:
            print(header)
            if 0 == page_counter:
                opus_identity_head = OPUS_IDENTITY_HEADER._make(struct.unpack(OPUS_IDENTITY_HEADER_FMT, content))
                print(opus_identity_head)
            #elif 1 == page_counter:
            #    opus_comment_head = OPUS_COMMENT_HEADER._make(struct.unpack(OPUS_COMMENT_HEADER_FMT, content))
            #    print(opus_comment_head)
            else:
                print(' '.join([hex(x) for x in content]))
                if page_counter > 1:
                    # show the TOC byte
                    toc = content[0]
                    config = (toc >> 3)
                    s = toc & 0b100
                    s = s >> 2
                    num_frames = toc & 0b11
                    print("config %d, s %d, c/frames %d" % (config, s, num_frames))

            page_counter += 1

        print("Read %d pages" % page_counter)

class srtp_ogg_opus_coder(ogg_opus_coder):
    '''
    Allow record srtp/rtp stream
    '''
    def __init__(self,rtp_header_len=12, udp_header_len=0,srtpkey=None,verbose=False):
        #super(ogg_opus_coder, self).__init__(verbose=verbose)
        ogg_opus_coder.__init__(self,verbose=verbose)
  
        # setup rtp parameters
        self.rtp_header_len = rtp_header_len
        self.udp_header_len = udp_header_len

        # setup srtp parameters
        self.srtpkey = srtpkey
        self.srtp_session = None
        self.ssrc = None


    def record_rtp_packet(self, packet,is_last=False):
        if self.ogg is None:
            print("No output file")
            return
        if not packet:
            print("No packet")
            return

        if self.verbose:
            print("Dumping packet ", packet)


        rtp_raw_full = None
        try:
            rtp_raw_full = bytes.fromhex(''.join(packet[self.udp_header_len:]))
        except:
            print("Failed to get hex", packet)
            return

        if self.verbose:
            print(self.udp_header_len, packet[self.udp_header_len-1])
            print(self.rtp_header_len, packet[self.udp_header_len])
            print(self.rtp_header_len, packet[self.udp_header_len+1])

        # decode RTP Header
        rtp_raw_header = rtp_raw_full[:12]

        if self.verbose:
            print(rtp_raw_header.hex())
        rtp = RTP_HEADER._make(struct.unpack(RTP_HEADER_FMT, rtp_raw_header))
        if self.verbose:
            print(rtp)

        # Filter the RTP
        if (rtp.FIRST & 0b10000000) != 0b10000000:
            print("Not an RTP")
            return

        # rtp_exten = rtp.FIRST & 0b1
        # Filter opus
        if rtp.PAYLOAD_TYPE != 111:
            print("Unknown payload ", rtp.PAYLOAD_TYPE)
            return

        if self.srtpkey:
            if self.ssrc != rtp.SSRC:
                print("using key [%s]" % self.srtpkey)
                #plc = Policy(key=self.srtpkey.encode("utf-8"),ssrc_type=Policy.SSRC_ANY_INBOUND)
                srtpkey = base64.b64decode(self.srtpkey)
                plc = Policy(key=srtpkey,ssrc_value=rtp.SSRC,ssrc_type=Policy.SSRC_ANY_INBOUND)
                #plc = Policy(key=srtpkey,ssrc_value=rtp.SSRC,ssrc_type=Policy.SSRC_ANY_INBOUND, SSRC_SPECIFIC=1)
                #plc = Policy(key=srtpkey,ssrc_type=Policy.SSRC_ANY_INBOUND)
                print(plc)
                self.srtp_session = Session(policy=plc)
                self.ssrc = rtp.SSRC
            try:
                rtp_raw_full = self.srtp_session.unprotect(rtp_raw_full)
            except:
                print("decrypt fail", rtp.SEQUENCE_NUMBER)
                return


        # Add bitstream header
        if self.ogg.get_curr_bitstream() != rtp.SSRC:
            self.write_stream_header(rtp.SSRC)
            self.write_stream_comment('hex_to_opus', [str(rtp)])

        rtp_payload = rtp_raw_full[self.rtp_header_len:]
        self.ogg.write_page(rtp_payload, is_data=True,is_last=is_last, ptime=20, pageno=rtp.SEQUENCE_NUMBER) # By default the ptime=20


    def record_rtp_file(self, infile, outfile):
        '''
        Convert an RTP hexdump into a recorded file
        '''
        self.start_file(outfile)
        with open(infile, 'r') as rtp_fd:
            packet_counter = 0
            packet = []
            for xline in rtp_fd:
                if ' ' not in xline or not xline:
                    if packet:
                        packet_counter += 1
                        self.record_rtp_packet(packet)
                        packet = []
                else:
                    content = xline.split()
                    #print(len(content))
                    content.pop(0) # skip the segment column
                    packet.extend(content)

            if packet:
                self.record_rtp_packet(packet,is_last=True)
        self.end_file()
        print("Written ", packet_counter, " packets")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='record opus rtp')
    parser.add_argument('--timestamp'
        , action='store_true'
        , help='Indicate if the timestamp is specified, TODO remove it')
    parser.add_argument('-v'
        , action='store_true'
        , help='Show verbose output')
    parser.add_argument('--hexfile'
        , required=False
        , help='Text output of pcap, hint `tshark -x -r file.pcap -Y "rtp && udp.srcport == myport" | cut -d " " -f 1-20 > strm_from_myport.txt` ')
    parser.add_argument('--outfile'
        , required=False
        , help='ogg formatted opus output file')
    parser.add_argument('--explainfile'
        , required=False
        , help='ogg formatted opus input file')
    parser.add_argument('--rtplen'
        , required=False
        , type=int
        , default=12
        , help='Length of rtp header, should be 12, see also --udplen')
    parser.add_argument('--udplen'
        , required=False
        , type=int
        , default=0
        , help='Length of udp header, should be 8 for IPV4')
                   

    # Support decryption
    parser.add_argument('--srtpkey'
        , required=False
        , default=None
        , help='srtpkey to decrypt the rtp')
                   
    args = parser.parse_args()
    if args.v:
        print(args)
    if args.hexfile and args.outfile:
        opusfile = srtp_ogg_opus_coder(rtp_header_len=args.rtplen,udp_header_len=args.udplen,verbose=args.v,srtpkey=args.srtpkey)
        opusfile.record_rtp_file(args.hexfile, args.outfile)
    if args.explainfile:
        opusfile = ogg_opus_coder(verbose=args.v)
        opusfile.explain_file(args.explainfile)

