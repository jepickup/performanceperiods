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

    #Converts hexadecimal packet data into integer form
    def hex_to_int(self, asc):
        h_string = ""
        for x in asc:
            h_string += "%02X" % ord(x)

        if h_string == "":
            h_string = "0x00"

        return int(h_string, 16)

    def hwdb_extract(self, filename, BIN_SIZE):

        f = open(filename, 'r')
        flow_lines = f.read().split('\n')

        flow_time_bins = []
        base_timestamp = int(int(((((flow_lines[0]).split('<|>'))[0]))[1:-1], 16)/1e9)

        for line in flow_lines:
            data_tuple = line.split('<|>')

            #Empty last line, dumb but works
            if(data_tuple[0] == ''):
                    break

            flow_key = (
                            data_tuple[2],      #SrcIP
                            data_tuple[4],      #DstIP
                            int(data_tuple[3]), #SrcPort
                            int(data_tuple[5]), #DstPort
                            int(data_tuple[1])  #Protocol
                        )

            flow_value = (
                                int(data_tuple[7]), #Bytes
                                int(data_tuple[6]), #Packets
                                1                   #Count
                            )

            flow_timestamp = int(int((data_tuple[0])[1:-1], 16)/1e9)
            bin_index = floor( (flow_timestamp - base_timestamp) / BIN_SIZE)

            if bin_index >= len(flow_time_bins):
                flow_time_bins.append({})
            
            if flow_key in (flow_time_bins[bin_index]):
                (flow_time_bins[bin_index])[flow_key] = tuple(map(sum,zip( (flow_time_bins[bin_index])[flow_key], flow_value )))
            else:
                (flow_time_bins[bin_index])[flow_key] = flow_value

        return flow_time_bins

    """
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


            TBD - Start or End time for flow timestamp
            self.hex_to_int(flow_packet[28:32]) / 1000,	#EndTime

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
    """

    def __init__(self):
        pass

if __name__ == "__main__":

# Method 1: Separation by time

    FE = FlowExtractor()
    flows = FE.hwdb_extract('Flows-20110620000001.data')
    print(len(flows),"flows extracted")
