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

    def retrieve_retries(self):
        
        #Step 1: Create a timeline of DHCP leases

        #DHCP file
        df = open('data/DHCP/dhcp' + self.filedate + '.db.dh', 'r')
        dhcp_lines = df.read().split('\n')
        
        dhcp_leases = {}
        
        for dhcp_line in dhcp_lines:
            
            if(len(dhcp_line) == 0):
                break

            dhcp_data = dhcp_line.split(';')
            dhcp_time = mktime( (datetime.strptime(dhcp_data[0], "%Y/%m/%d:%H:%M:%S")).timetuple() )	

            action, mac, ip = dhcp_data[1], dhcp_data[2].replace(':', ''), dhcp_data[3]

            if mac not in dhcp_leases:
                dhcp_leases[mac] = []

            if action == "add":
                (dhcp_leases[mac]).append( (dhcp_time, dhcp_time+86400, ip) )
            elif action == "upd" or action == "old":
                if len(dhcp_leases[mac]) > 0:
                    original_tuple = dhcp_leases[mac][ len(dhcp_leases[mac]) - 1 ]
                    ((dhcp_leases[mac])[ len(dhcp_leases[mac]) - 1 ]) = (original_tuple[0], dhcp_time, ip)
                (dhcp_leases[mac]).append( (dhcp_time, dhcp_time+86400, ip) )
            elif action == "del":
                if len(dhcp_leases[mac]) > 0:
                    original_tuple = dhcp_leases[mac][ len(dhcp_leases[mac]) - 1 ]
                    ((dhcp_leases[mac])[ len(dhcp_leases[mac]) - 1 ]) = (original_tuple[0], dhcp_time, ip)
            else:
                print "Unknown action!"
                continue

        #Step 2: Step through link events, updating DHCP table and recording nretries

        #Link file
        lf = open('data/LINKS/link' + self.filedate + '.db.lt', 'r')
        link_lines = lf.read().split('\n')

        dhcp_time = 0
        lease_table = {}
        latest_time = 0
        for link_line in link_lines:
            
            if len(link_line) == 0:
                break

            link_time = int(int(link_line[1:17], 16)/1e9)
            link_line = link_line[19:]

            link_data = link_line.split(';')

            mac, nretries = link_data[0], link_data[2]

            del_table = []
            #Bring DHCP leases up to speed
            if dhcp_time < link_time:
                for mac_lease in dhcp_leases:
                    lease_count = 0
                    while len(dhcp_leases[mac_lease]) > 0:
                        lease_record = dhcp_leases[mac_lease][0]
                        if link_time >= lease_record[0] and link_time < lease_record[1]:
                            lease_table[mac_lease] = lease_record[2]
                            latest_time = link_time 
                            break
                        elif link_time >= lease_record[0]:
                            del( dhcp_leases[mac_lease][0] )
                            if mac_lease in lease_table:
                                del( lease_table[mac_lease] )
                        else:
                            latest_time = link_time 
                            break
            dhcp_time = latest_time 
            bdkeys = self.breakdowns.keys()
            bdkeys.sort(reverse=True)
            ts = [i for i in bdkeys if i < link_time]
            if ts:
                ts = max(ts)
                if mac in lease_table and int(nretries) > 0 and (ts+60 > link_time):
                    ip = lease_table[mac]
                    self.breakdowns[ts]['nretries'] += int(nretries)
                    if ip in self.breakdowns[ts]['internal']:
                        self.breakdowns[ts]['internal'][ip]['nretries'] += int(nretries)

    def calculate_breakdown(self, flows):

        breakdown =     {
                            'protocols'    	: {},
                            'internal'         : {}, # IP: { 'in_bytes/pkts/flows':0, 'out_bytes/pkts/flows':0 }
                            'external'         : {},
                            'nretries'         : 0,
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

            if IntIP not in breakdown['internal']:
                (breakdown['internal'])[IntIP] = {
                                                    'in_bytes'  : 0,
                                                    'in_pkts'   : 0,
                                                    'in_flows'  : 0,
                                                    'out_bytes' : 0,
                                                    'out_pkts'  : 0,
                                                    'out_flows' : 0,
                                                    'nretries'  : 0,
                                                    'ip_freq'   : {} # Frequency of specific IP to an external IP
                                                }

            if ExtIP not in breakdown['external']:
                (breakdown['external'])[ExtIP] = {
                                                    'in_bytes'  : 0,
                                                    'in_pkts'   : 0,
                                                    'in_flows'  : 0,
                                                    'out_bytes' : 0,
                                                    'out_pkts'  : 0,
                                                    'out_flows' : 0,
                                                    'ip_freq'   : {} # Frequency of specific IP to an external IP
                                                }

            if SrcIP == IntIP:  # Outbound
                ((breakdown['internal'])[IntIP])['out_bytes']   += flow_data[0] 
                ((breakdown['internal'])[IntIP])['out_pkts']    += flow_data[1]
                ((breakdown['internal'])[IntIP])['out_flows']   += flow_data[2]
                ((breakdown['external'])[ExtIP])['out_bytes']   += flow_data[0] 
                ((breakdown['external'])[ExtIP])['out_pkts']    += flow_data[1]
                ((breakdown['external'])[ExtIP])['out_flows']   += flow_data[2]
                breakdown['out_bytes'] += flow_data[0]
                breakdown['out_pkts'] += flow_data[1]
                breakdown['out_flows'] += flow_data[2]

            else:               # Inbound
                ((breakdown['internal'])[IntIP])['in_bytes']   += flow_data[0] 
                ((breakdown['internal'])[IntIP])['in_pkts']    += flow_data[1]
                ((breakdown['internal'])[IntIP])['in_flows']   += flow_data[2]
                ((breakdown['external'])[ExtIP])['in_bytes']   += flow_data[0] 
                ((breakdown['external'])[ExtIP])['in_pkts']    += flow_data[1]
                ((breakdown['external'])[ExtIP])['in_flows']   += flow_data[2]
                breakdown['in_bytes'] += flow_data[0]
                breakdown['in_pkts'] += flow_data[1]
                breakdown['in_flows'] += flow_data[2]

                if ExtIP in breakdown['internal'][IntIP]['ip_freq']:
                    breakdown['internal'][IntIP]['ip_freq'][ExtIP] += flow_data[2]
                else:
                    breakdown['internal'][IntIP]['ip_freq'][ExtIP] = flow_data[2]

                if IntIP in breakdown['external'][ExtIP]['ip_freq']:
                    breakdown['external'][ExtIP]['ip_freq'][IntIP] += flow_data[2]
                else:
                    breakdown['external'][ExtIP]['ip_freq'][IntIP] = flow_data[2]

            if flow_key[2] not in breakdown['protocols']:
                (breakdown['protocols'])[flow_key[4]] = 0

            (breakdown['protocols'])[flow_key[4]] += flow_data[2]

        return breakdown

    def hwdb_extract(self, filedate, start_time_count=0, end_time_count=1440, BIN_SIZE=60):

        self.filedate = filedate
        print "Started extraction.."

        #Flow file
        ff = open('data/FLOWS/Flow' + self.filedate + '.db.dt', 'r')
        print ff
        flow_lines = ff.read().split('\n')
        print len(flow_lines)
        flow_breakdowns = {}
        flow_bin = {}

        start_timestamp = base_timestamp = mktime( (datetime.strptime((flow_lines[0])[0:19], "%Y/%m/%d:%H:%M:%S")).timetuple() )
        print "Initial timestamp", start_timestamp        
        #Modify start according to start_time_count
        start_timestamp += ( (start_time_count-1) * 60)
        print "Modified timestamp", start_timestamp
        end_timestamp = start_timestamp + BIN_SIZE
        
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

        self.retrieve_retries()
        return (self.breakdowns, self.ip_list)

    def __init__(self):
        self.filedate    = ''
        self.ip_list     = []
        self.breakdowns  = {}

if __name__ == "__main__":

# Method 1: Separation by time

    FE = FlowExtractor()
    flows = FE.hwdb_extract('20101219000001')
    print(len(flows),"flows extracted")
