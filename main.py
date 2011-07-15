"""
    performanceperiods
    ---
    Extracts useful metrics from hwdb .data files that
    are mapped onto graphs to assess the feasability
    of metrics for signalling network health to a user
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

    if( f.read(1) != '@' ):
        print("File must begin with @")
        sys.exit(0)

    while True:
        timestamp   = ""
        data        = ""

        #Read timestamp
        time_byte = f.read(1)

        while( time_byte != '@' ):
            timestamp += time_byte
            time_byte = f.read(1)
                        
        #Read data up until next timestamp
        data_byte = f.read(1)
        while( data_byte != '@' ):
            #No more data
            if data_byte == '':
                f.close()
                return flows
            data += data_byte
            data_byte = f.read(1)

        #Remove leading and trailing <|>
        data = data[3:-4]

        data_tuple = data.split('<|>')

        flows.append(
                    FlowTuple(
                                timestamp,
                                data_tuple[1],   #SrcIP
                                data_tuple[2],   #DstIP
                                data_tuple[3],   #SrcPort
                                data_tuple[4],   #DstPort
                                data_tuple[6],   #Bytes
                                data_tuple[5],   #Packets
                                data_tuple[0]   #Protocol
                                )
                    )


flow_list = extract_flows('Flows-20110619231749.data')

print(len(flow_list))
