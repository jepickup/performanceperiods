"""
    performanceperiods
    ---
    Extracts useful metrics from hwdb .data files
    and then maps them onto graphs to assess their
    feasibility for demonstrating network health
    ---
    Author: James Pickup <FORENAME AT eSURNAME dot co dot uk>
    ---

    To begin with, everything will be clumped in main.py and
    eventually abstracted out into relevant classes
"""

import sys, collections, time
from math import floor

class FlowExtractor:

    #Data structure for storing individual flow entries
    FlowTuple = collections.namedtuple('FlowTuple', 'Timestamp SrcIP DstIP SrcPort DstPort Bytes Packets Protocol')

    flow_count          = 0

    #Converts hexadecimal packet data into integer form
    def hex_to_int(self, asc):
        h_string = ""
        for x in asc:
            h_string += "%02X" % ord(x)

        if h_string == "":
            h_string = "0x00"

        return int(h_string, 16)

    def hwdb_extract(self, filename):

        flow_list = []
        f = open(filename, 'r')
        flow_lines = f.read().split('\n')

        for line in flow_lines:
            data_tuple = line.split('<|>')

            #Empty last line, dumb but works
            if(data_tuple[0] == ''):
                    break

            flow_list.append(
                    self.FlowTuple(
                            int(int((data_tuple[0])[1:-1], 16)/1e9), #Timestamp
                            data_tuple[2],   #SrcIP
                            data_tuple[4],   #DstIP
                            int(data_tuple[3]),   #SrcPort
                            int(data_tuple[5]),   #DstPort
                            int(data_tuple[7]),   #Bytes
                            int(data_tuple[6]),   #Packets
                            int(data_tuple[1])    #Protocol
                            )
                    )

        return flow_list

    #Extracts individual flow entries per packet from a .pcap file of NetFlow v5 UDP packets
    def pcap_extract(self, filename):
        
        flow_list = []
        system_uptime = system_timestamp = 0
        p = pcap.pcapObject()
        packet_data = p.open_offline(filename)
	
        if not system_uptime or not self.system_timestamp:
            system_uptime 	= self.hex_to_int(packet_data[46:50]) / 1000 	#Seconds since RFlow started
            system_timestamp 	= self.hex_to_int(packet_data[50:54])			#UNIX timestamp of router
            flow_packet = packet_data[66:] #Shift past header
            
        start_count = self.flow_count #Hold position to calculate FlowSequence
        
        while(len(flow_packet) > 0):

            SrcIP, DstIP 	= socket.inet_ntoa(flow_packet[0:4]), socket.inet_ntoa(flow_packet[4:8])
            SrcPort, DstPort	= self.hex_to_int(flow_packet[32:34]), self.hex_to_int(flow_packet[34:36])

            """
            TBD - Start or End time for flow timestamp
            self.hex_to_int(flow_packet[28:32]) / 1000,	#EndTime
            """
            flow_list.append(
                            self.FlowTuple(
                                self.hex_to_int(flow_packet[24:28]) / 1000,	#StartTime - Timestamp
                                SrcIP,						#SrcIP
                                DstIP,						#DstIP
                                SrcPort,					#SrcPort
                                DstPort,					#DstPort
                                int(self.hex_to_int(flow_packet[20:24])), 	#Bytes, (logarithm to base 2 and rounded to an integer)
                                int(self.hex_to_int(flow_packet[16:20])),	#Packets, (logarithm to base 2 and rounded to an integer)
                                self.hex_to_int(flow_packet[38]),		#Protocol
                                )
                            )

            flow_packet = flow_packet[48:] #Shift to next flow entry
            self.flow_count += 1

        return flow_list

    def convert_bytes(self,bytes):
        bytes = float(bytes)
        if bytes >= 1073741824:
            gigabytes = bytes / 1073741824
            size = '%.2fG' % gigabytes
        elif bytes >= 1048576:
            megabytes = bytes / 1048576
            size = '%.2fM' % megabytes
        elif bytes >= 1024:
            kilobytes = bytes / 1024
            size = '%.2fK' % kilobytes
        else:
            size = '%.2fb' % bytes
        return size

    def __init__(self):
        pass

if __name__ == "__main__":

# Method 1: Separation by time

    FE = FlowExtractor()
    flows = FE.hwdb_extract('Flows-20110620000001.data')
    print(len(flows),"flows extracted")

    flow_time_bins = []
    
    base_timestamp = flows[0].Timestamp
    
    for flow in flows:
        bin_index = floor( (flow.Timestamp - base_timestamp) / 60 )

        if bin_index >= len(flow_time_bins):
            flow_time_bins.append([])
        
        (flow_time_bins[bin_index]).append(flow)

    for bin_index, bin in enumerate(flow_time_bins):
        bin_bytes = bin_packets = 0

        for flow in bin:
            bin_bytes += flow.Bytes
            bin_packets += flow.Packets

        print("Time", str(bin_index) + ", Bytes:", FE.convert_bytes(bin_bytes), "Packets:", bin_packets);
        
# Method 2: Separation by number of flows

# Method 3: Dynamic separation by flows/time ?
