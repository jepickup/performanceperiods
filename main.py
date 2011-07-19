"""
    performanceperiods
    ---
    Author: James Pickup <FORENAME at eSURNAME dot co dot uk>
    ---
"""

import re
from math import floor
from FlowExtractor import FlowExtractor

BIN_SIZE = 60

def convert_bytes(bytes):
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

# Method 1: Separation by time

# Flow statistics
total_bytes = total_packets = total_occurrences = 0

FE = FlowExtractor()
flows = FE.hwdb_extract('Flows-20110620000001.data', BIN_SIZE)
print(len(flows), str(BIN_SIZE) + "-second periods extracted")

ip_time_bins = {}

ip_match = re.compile('^10.')

for time, time_bin in enumerate(flows):

    for fkey, fdata in time_bin.items():
        
        if ip_match.match((fkey[0])):
            InternalIP = fkey[0]
        else:
            InternalIP = fkey[1]

        total_bytes += fdata[0]
        total_packets += fdata[1]
        total_occurrences += fdata[2]
        
        data_tuple = ( fdata[0], fdata[1], fdata[2] )
       
        if (time, InternalIP) in ip_time_bins:
            ip_time_bins[ (time, InternalIP) ] = tuple(map(sum,zip( ip_time_bins[ (time, InternalIP) ], data_tuple)))
        else:
            ip_time_bins[ (time, InternalIP) ] = data_tuple

ip_tb_list = list(ip_time_bins)
ip_tb_list.sort()

print( "IP-Timestamps:", len(ip_tb_list) )
print( "Bandwidth:", convert_bytes(total_bytes) )
print( "Packets:", convert_bytes(total_packets) )
print( "Occurrences:", total_occurrences )

# Method 2: Separation by number of flows

# Method 3: Dynamic separation by flows/time ?
