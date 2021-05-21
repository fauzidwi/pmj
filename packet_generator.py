import sys
import getopt
from scapy.all import *
from scapy import all as scapy
from random import randrange
from scapy.utils import PcapWriter
import string
import time

def sourceipgen(dstIP, srcIP, dstPrt, srcPrt, macSrc, macDst, tyPee, coDee, chkSum, idNtfier):
    tip = dstIP
    sip = srcIP
    tpr = dstPrt
    spr = srcPrt
    ms = macSrc
    md = macDst
    tpe = tyPee
    cde = coDee
    csm = chkSum
    idf = idNtfier
    not_valid = [10, 127, 254, 255, 1, 2, 169, 172, 192]
    icmpExcp = [2,3,4,5,7]
    icmpExcp2 = randrange(44, 252)
    first = randrange(1, 256)
    # tuwooo = randrange(0, 255)
    tuwooo = randrange(0, 8)
    if dstIP == '':
        while first in not_valid:
            first = randrange(1, 256)
        tip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    if srcIP == '':
        while first in not_valid:
            first = randrange(1, 256)
        sip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    if dstPrt == '':
        tpr = random.randint(1, 1024)
    if srcPrt == '':
        spr = random.randint(1, 1024)
    if macSrc == '':
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        ms = ':'.join(map(lambda x: "%02x" % x, mac))
    if macDst == '':
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        md = ':'.join(map(lambda x: "%02x" % x, mac))
    if tyPee == '':
        hexDmp = "".join([chr(random.randint(0x00, 0xff)), chr(random.randint(0x00, 0xff)), chr(random.randint(0x00, 0xff))])
        hexDmp2 = "".join([chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x00),chr(0x10),chr(0x11),chr(0x12),chr(0x13),chr(0x14),chr(0x15),chr(0x16),chr(0x17),chr(0x18),chr(0x19),chr(0x1a),chr(0x1b),chr(0x1c),chr(0x1d),chr(0x1e),chr(0x1f)])
        hexDmp3 = "".join([chr(0x20),chr(0x21),chr(0x22),chr(0x23),chr(0x24),chr(0x25),chr(0x26),chr(0x27),chr(0x28),chr(0x29),chr(0x2a),chr(0x2b),chr(0x2c),chr(0x2d),chr(0x2e),chr(0x2f),chr(0x30),chr(0x31),chr(0x32),chr(0x33),chr(0x34),chr(0x35),chr(0x36),chr(0x37),])
        tpe = "".join([hexDmp, hexDmp2, hexDmp3])
    if coDee == '':
        cde = random.randint(1, 40000)
    if chkSum == '':
        csm = random.randint(1, 40000)
    if idNtfier == '':
        idf = random.randint(10000, 50000)
    return (tip, sip, tpr, spr, ms, md, tpe, cde, csm, idf)

def main(argv):
    dstIP = ''
    srcIP = ''
    count = ''
    dstPrt = ''
    srcPrt = ''
    ptCl = ''
    macSrc = ''
    macDst = ''
    leng = ''
    tyPee = ''
    coDee = ''
    chkSum = ''
    idNtfier = ''
    try:
        opts, args = getopt.getopt(argv, "hd:s:c:e:r:p:u:j:", ["tgt=", "src=", "ct=", "et=", "tp=", "sp=", "pt=", "rt="])
    except getopt.GetoptError:
        print "not defined !!!!!"
        print "\tpacket_generator.py -h <help>"
        sys.exit(2)
    if len(sys.argv) < 2:
        print "packet_generator.py -h <help>"
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print "packet_generator.py [options]"
            print "option lists :"
            print "\t-d [ip]: destination_IP_leave_blank_for_random"
            print "\t-s [ip]: source_IP_leave_blank_for_random"
            print "\t-c [mac]: MAC_source_leave_blank_for_random"
            print "\t-e [mac]: MAC_destination_leave_blank_for_random"
            print "\t-r [port]: destination_port_leave_blank_for_random"
            print "\t-p [port]: source_port_leave_blank_for_random"
            print "\t-u [udp/tcp/icmp]: protocol_udp_or_tcp_syn_default_udp"
            print "\t-j [count]: state_packet_count_default_1000"
            sys.exit()
        elif opt in ("-d", "--tgt"):
            dstIP = arg
        elif opt in ("-s", "--src"):
            srcIP = arg
        elif opt in ("-c", "--ct"):
            macSrc = arg
        elif opt in ("-e", "--et"):
            macDst = arg
        elif opt in ("-r", "--tp"):
            dstPrt = arg
        elif opt in ("-p", "--sp"):
            srcPrt = arg
        elif opt in ("-u", "--pt"):
            ptCl = arg
        elif opt in ("-j", "--rt"):
            leng = arg

    filename = ptCl + str(leng) + "packets.pcap"
    pktdump = PcapWriter(filename, append=True, sync=True)

    def create_packets(self):
        self.msg("creating packets")

    if leng == '':
        leng = '1000'

    if ptCl == 'udp' or ptCl == '':
        for j in xrange(int(leng)):
            x = sourceipgen(dstIP, srcIP, dstPrt, srcPrt, macSrc, macDst, tyPee, coDee, chkSum, idNtfier)
            packets = Ether(src=x[4], dst=x[5], type=0x800)/IP(dst=x[0], src=x[1], proto=17)/UDP(dport=int(x[2]), sport=int(x[3]))/Raw(load=('DOS_TEST_AGAINTS_CONTROLLER'))
            pktdump.write(packets)
            print(j)

    elif ptCl == 'tcp':
        for j in xrange(int(leng)):
            x = sourceipgen(dstIP, srcIP, dstPrt, srcPrt, macSrc, macDst, tyPee, coDee, chkSum, idNtfier)
            packets = Ether(src=x[4], dst=x[5], type=0x800)/IP(src=x[1], dst=x[0], ttl=250, proto=6)/TCP(sport=int(x[3]), dport=int(x[2]), seq=12345, ack=0, window=1000, flags="S")
            pktdump.write(packets)
            print(j)

    elif ptCl == 'icmp':
        for j in xrange(int(leng)):
            x = sourceipgen(dstIP, srcIP, dstPrt, srcPrt, macSrc, macDst, tyPee, coDee, chkSum, idNtfier)
            y = sourceipgen(dstIP, srcIP, dstPrt, srcPrt, macSrc, macDst, tyPee, coDee, chkSum, idNtfier)
            packets = Ether(src=x[4], dst=x[5], type=0x800)/IP(id=int(x[9]) ,src=x[1], dst=x[0], flags=0x2, ttl=64, proto=1)/ICMP(type=8, code=0, id=int(x[7]), seq=int(x[8]))/Raw(load=x[6])
            # packets2 = Ether(src=x[5], dst=x[4], type=0x800)/IP(id=int(y[9]) ,src=x[0], dst=x[1], flags=0x0, ttl=64, proto=1)/ICMP(type=0, code=0, id=int(x[7]), seq=int(x[8]))/Raw(load=x[6])
            pktdump.write(packets)
            # pktdump.write(packets2)
            print(j)


if __name__ == "__main__":
    main(sys.argv[1:])
