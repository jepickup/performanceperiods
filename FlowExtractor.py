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
import re
from math import floor
from datetime import datetime
from time import mktime

class FlowExtractor:
 
    def calculate_breakdown(self, flows):

        breakdown               = {}
        breakdown['protocols']  = {}
        breakdown['internal']   = {} # IP: { 'in_bytes/pkts/flows':0, 'out_bytes/pkts/flows':0 }
        breakdown['external']   = {}

        ip_match = re.compile('^192\.')

        for flow_key, flow_data in flows.items():

            SrcIP, DstIP = flow_key[0], flow_key[1]

            if ip_match.match(flow_key[0]):
                IntIP, ExtIP = flow_key[0], flow_key[1]
            elif ip_match.match(flow_key[1]):
                IntIP, ExtIP = flow_key[1], flow_key[0]
            else:
                continue # Ignore non-host flows?

            if IntIP not in breakdown['internal']:
                (breakdown['internal'])[IntIP] = {
                                                    'in_bytes'  : 0,
                                                    'in_pkts'   : 0,
                                                    'in_flows'  : 0,
                                                    'out_bytes' : 0,
                                                    'out_pkts'  : 0,
                                                    'out_flows' : 0
                                                }

            if ExtIP not in breakdown['external']:
                (breakdown['external'])[ExtIP] = {
                                                    'in_bytes'  : 0,
                                                    'in_pkts'   : 0,
                                                    'in_flows'  : 0,
                                                    'out_bytes' : 0,
                                                    'out_pkts'  : 0,
                                                    'out_flows' : 0
                                                }

            if SrcIP == IntIP:  # Internal outbound
                ((breakdown['internal'])[IntIP])['out_bytes']   += flow_data[0] 
                ((breakdown['internal'])[IntIP])['out_pkts']    += flow_data[1]
                ((breakdown['internal'])[IntIP])['out_flows']   += flow_data[2]
                ((breakdown['external'])[ExtIP])['out_bytes']   += flow_data[0] 
                ((breakdown['external'])[ExtIP])['out_pkts']    += flow_data[1]
                ((breakdown['external'])[ExtIP])['out_flows']   += flow_data[2]
            else:               # Internal inbound
                ((breakdown['internal'])[IntIP])['in_bytes']   += flow_data[0] 
                ((breakdown['internal'])[IntIP])['in_pkts']    += flow_data[1]
                ((breakdown['internal'])[IntIP])['in_flows']   += flow_data[2]
                ((breakdown['external'])[ExtIP])['in_bytes']   += flow_data[0] 
                ((breakdown['external'])[ExtIP])['in_pkts']    += flow_data[1]
                ((breakdown['external'])[ExtIP])['in_flows']   += flow_data[2]

            breakdown['total_bytes']                = flow_data[0]
            breakdown['total_pkts']                 = flow_data[1]
            breakdown['total_flows']                = flow_data[2]

            if flow_key[2] not in breakdown['protocols']:
                (breakdown['protocols'])[flow_key[4]] = 0

            (breakdown['protocols'])[flow_key[4]] += flow_data[2]

            #Wireless signal TODO
        return breakdown

    def hwdb_extract(self, filename, BIN_SIZE):

        f = open(filename, 'r')
        flow_lines = f.read().split('\n')
        flow_breakdowns = {}
        flow_bin = {}

        start_timestamp = base_timestamp = mktime( (datetime.strptime((flow_lines[0])[0:19], "%Y/%m/%d:%H:%M:%S")).timetuple() )
        end_timestamp = start_timestamp + BIN_SIZE

        for line in flow_lines:

            if(len(line) == 0):
                break

            flow_timestamp = mktime( (datetime.strptime(line[0:19], "%Y/%m/%d:%H:%M:%S")).timetuple() )

            data_tuple = line[20:].split(':')

            flow_key = (
                            data_tuple[1],      #SrcIP
                            data_tuple[2],      #DstIP
                            int(data_tuple[3]), #SrcPort
                            int(data_tuple[4]), #DstPort
                            int(data_tuple[0])  #Protocol
                        )

            flow_value = (
                                int(data_tuple[7]), #Bytes
                                int(data_tuple[6]), #Packets
                                1                   #Count
                            )

            if flow_timestamp >= start_timestamp and flow_timestamp < end_timestamp:
                if flow_key in flow_bin:
                    flow_bin[flow_key] = tuple(map(sum,zip( flow_bin[flow_key], flow_value )))
                else:
                    flow_bin[flow_key] = flow_value
            elif flow_timestamp < start_timestamp:
                sys.exit("Error, past flow after present flow")
            else:
                flow_breakdowns[start_timestamp] = self.calculate_breakdown(flow_bin)
                flow_bin.clear()
                start_timestamp = end_timestamp
                end_timestamp = start_timestamp + BIN_SIZE
                #break

        return flow_breakdowns

    def __init__(self):
        pass

if __name__ == "__main__":

# Method 1: Separation by time

    FE = FlowExtractor()
    flows = FE.hwdb_extract('data/FLOWS/Flow20101219000001.db.dt', 60)
    print(len(flows),"flows extracted")
