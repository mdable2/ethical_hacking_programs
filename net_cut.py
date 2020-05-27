# Must use Python 2.7.18 64-bit interpreter
# Meaning, you use python (not python3) to run program from command line
import netfilterqueue

def process_packet(packet):
    print(packet)

# Connect to iptables queue created
# process_packet is call back function, runs for each packet
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()