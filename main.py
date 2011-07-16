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

#Data structure for storing individual flow entries
FlowTuple = collections.namedtuple('FlowTuple', 'Timestamp SrcIP DstIP SrcPort DstPort Bytes Packets Protocol')

flow_list           = []
flow_time_bins      = []
flow_count          = 0

def extract_flows(filename):
    
    flows = []
    f = open(filename, 'r')
    flow_lines = f.read().split('\n')
    
    for line in flow_lines:
        data_tuple = line.split('<|>')
        
        #Empty last line, dumb but works
        if(data_tuple[0] == ''):
                break

        flows.append(
                FlowTuple(
                        int(int((data_tuple[0])[1:-1], 16)/1e9), #Timestamp
			data_tuple[2],   #SrcIP
			data_tuple[4],   #DstIP
			data_tuple[3],   #SrcPort
			data_tuple[5],   #DstPort
			data_tuple[7],   #Bytes
		        data_tuple[6],   #Packets
			data_tuple[1]    #Protocol
                	)
		)
	
    return flows

flow_list = extract_flows('Flows-20110619231749.data')

print(len(flow_list),"flows extracted")
