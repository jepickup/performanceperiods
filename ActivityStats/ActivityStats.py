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

class ActivityStats:

    def calculate_breakdown(self, flows):

        breakdown =     {
                            'ip_stats'         : {},
                            'in_bytes'       	: 0,
                            'out_bytes'       	: 0,
                            'in_pkts'       	: 0,
                            'out_pkts'    	: 0,
                            'in_flows'         : 0,
                            'out_flows'     : 0
                        }

        ip_match = re.compile('^192\.168')

        for flow_key, flow_data in flows.items():

            SrcIP, DstIP = flow_key[0], flow_key[1]

            if ip_match.match(flow_key[0]):
                IntIP, ExtIP = flow_key[0], flow_key[1]
            elif ip_match.match(flow_key[1]):
                IntIP, ExtIP = flow_key[1], flow_key[0]
            else:
                continue # Ignore non-host flows?

            if IntIP not in self.ip_list:
                self.ip_list.append(IntIP)

            if IntIP not in breakdown['ip_stats']:
                (breakdown['ip_stats'])[IntIP] = {
                                                    'in_bytes'  : 0,
                                                    'in_pkts'   : 0,
                                                    'in_flows'  : 0,
                                                    'out_bytes' : 0,
                                                    'out_pkts'  : 0,
                                                    'out_flows' : 0,
                                                }

            if SrcIP == IntIP:  # Outbound
                ((breakdown['ip_stats'])[IntIP])['out_bytes']   += flow_data[0] 
                ((breakdown['ip_stats'])[IntIP])['out_pkts']    += flow_data[1]
                ((breakdown['ip_stats'])[IntIP])['out_flows']   += flow_data[2]
                breakdown['out_bytes'] += flow_data[0]
                breakdown['out_pkts'] += flow_data[1]
                breakdown['out_flows'] += flow_data[2]

            else:               # Inbound
                ((breakdown['ip_stats'])[IntIP])['in_bytes']   += flow_data[0] 
                ((breakdown['ip_stats'])[IntIP])['in_pkts']    += flow_data[1]
                ((breakdown['ip_stats'])[IntIP])['in_flows']   += flow_data[2]
                breakdown['in_bytes'] += flow_data[0]
                breakdown['in_pkts'] += flow_data[1]
                breakdown['in_flows'] += flow_data[2]

        return breakdown

    def hwdb_extract(self, filedate, start_time_count=1, end_time_count=1440, BIN_SIZE=60):

        self.filedate = filedate
        print "Started extraction.."

        #Flow file
        ff = open('../data/FLOWS/Flow' + self.filedate + '.db.dt', 'r')
        flow_lines = ff.read().split('\n')
        flow_breakdowns = {}
        flow_bin = {}

        start_timestamp = base_timestamp = mktime( (datetime.strptime((flow_lines[0])[0:19], "%Y/%m/%d:%H:%M:%S")).timetuple() )
        end_timestamp = start_timestamp + BIN_SIZE
        print start_timestamp, end_timestamp
        
        time_count = 1

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
                continue
            else:
                print "Calling breakdown..", time_count
                self.breakdowns[start_timestamp] = self.calculate_breakdown(flow_bin)
                flow_bin.clear()
                start_timestamp = end_timestamp
                end_timestamp = start_timestamp + BIN_SIZE
                time_count += 1
                if time_count > (end_time_count - (start_time_count-1)):
                    break

        print "Final call with", len(flow_bin)
        self.breakdowns[start_timestamp] = self.calculate_breakdown(flow_bin)


        return (self.breakdowns, self.ip_list)

    def __init__(self):
        self.filedate    = ''
        self.ip_list     = []
        self.breakdowns  = {}

if __name__ == "__main__":

# Method 1: Separation by time

    file_str = raw_input("Enter a file time to process: ")

    FE = FlowExtractor()
    flows, iplist = FE.hwdb_extract(file_str, 1, 1440, 3660)
    print flows
    print(len(flows),"flows extracted")
