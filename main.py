"""
    performanceperiods
    ---
    Author: James Pickup <FORENAME at eSURNAME dot co dot uk>
    ---
"""

from FlowExtractor import FlowExtractor
from pyrrd.rrd import RRD, RRA, DS
from pyrrd.graph import DEF, CDEF, VDEF
from pyrrd.graph import LINE, AREA, GPRINT
from pyrrd.graph import ColorAttributes, Graph

BIN_SIZE = 60

# Method 1: Separation by time

FE = FlowExtractor()
flows = FE.hwdb_extract('data/FLOWS/Flow20101219000001.db.dt', BIN_SIZE)

keys = flows.keys()
keys.sort()

startTime = int(keys[0])
filename = 'perf.rrd'

dss, rras = [], []

dss.append(DS(dsName='total_bytes', dsType='ABSOLUTE', heartbeat=900))

# 1 days-worth of one-minute samples --> 60/1 * 24
rra1 = RRA(cf='AVERAGE', xff=0, steps=1, rows=1440)
# 7 days-worth of five-minute samples --> 60/5 * 24 * 7
rra2 = RRA(cf='AVERAGE', xff=0, steps=5, rows=2016)
# 30 days-worth of five-minute samples --> 60/60 * 24 * 30
rra3 = RRA(cf='AVERAGE', xff=0, steps=60, rows=720)
rras.extend([rra1, rra2, rra3])

myRRD = RRD(filename, step=60, ds=dss, rra=rras, start=startTime-60)
myRRD.create(debug=False)

counter = 0
for flow_key in keys:
    print "Adding to RRD" + str(flow_key) + " " + str(int(flow_key))
    myRRD.bufferValue(int(flow_key), (flows[flow_key])['total_bytes'])
    counter += 1
    if counter % 100 == 0:
        myRRD.update()

myRRD.update()

print myRRD

# Method 2: Separation by number of flows

# Method 3: Dynamic separation by flows/time ?
