# pmj

Running file :
--------------------------------------------------------
python packet-generator.py -h
packet_generator.py [options]
option lists :
	-d [ip]: destination_IP_leave_blank_for_random
	-s [ip]: source_IP_leave_blank_for_random
	-c [mac]: MAC_source_leave_blank_for_random
	-e [mac]: MAC_destination_leave_blank_for_random
	-r [port]: destination_port_leave_blank_for_random
	-p [port]: source_port_leave_blank_for_random
	-u [udp/tcp/icmp]: protocol_udp_or_tcp_syn_default_udp
	-j [count]: state_packet_count_default_1000

--------------------------------------------------------

python entropy.py

by default will generate entropyDDos.txt, entropyNormal.txt files for storing entropy values as well as PacketMHN directory to store mongoDB dataset each 50 seconds. 
