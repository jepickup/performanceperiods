#!/usr/bin/python2.7
"""
    performanceperiods
    ---
    Author: James Pickup <FORENAME at eSURNAME dot co dot uk>
    ---
"""

from FlowExtractor import FlowExtractor
from math import log
from pyrrd.rrd import RRD, RRA, DS
from pyrrd.graph import DEF, CDEF, VDEF
from pyrrd.graph import LINE, AREA, GPRINT
from pyrrd.graph import ColorAttributes, Graph
import os, re
from math import log

flow_entropies = {}
delta_flow_entropies = {}

rras = []
rra1 = RRA(cf='AVERAGE', xff=0, steps=1, rows=1440)
rra1a = RRA(cf='LAST', xff=0, steps=1, rows=1440)
rra2 = RRA(cf='AVERAGE', xff=0, steps=5, rows=2016)
rra3 = RRA(cf='AVERAGE', xff=0, steps=60, rows=720)
rras.extend([rra1, rra1a, rra2, rra3])

def calculate_entropies():

    last_key = 0
    last_entropies = []
    
    for flow_key in keys:

        entropies = { 'global_internal' : 0, 'global_external' : 0, 'internal' : {}, 'external' : {} } 

        total_flows      = flows[flow_key]['in_flows'] + flows[flow_key]['out_flows']

        for loc in ['internal', 'external']:
            for IP in flows[flow_key][loc]:
                
                n_over_s = float(flows[flow_key][loc][IP]['in_flows'] + flows[flow_key][loc][IP]['out_flows']) / float(total_flows)

                #Global entropy for Int/Ext IP
                if n_over_s:
                    entropies['global_' + loc]      += -( n_over_s ) * log( (n_over_s), 2)
                #IP entropy
                for dyn_IP in flows[flow_key][loc][IP]['ip_freq']:
                    ip_n_over_s = float(flows[flow_key][loc][IP]['ip_freq'][dyn_IP]) / float(total_flows)
                    #Fix, terribllll
                    if IP in entropies[loc]:
                        entropies[loc][dyn_IP] += -( ip_n_over_s ) * log( (n_over_s), 2)
                    else:
                        entropies[loc][dyn_IP] = -( ip_n_over_s ) * log( (n_over_s), 2)


        flow_entropies[flow_key]   = entropies
        
        if flow_key != keys[0]:
            delta = {}

            for key in ['internal', 'external']:

                delta[key] = {}
                delta['global_' + key] = entropies['global_' + key] - last_entropies['global_' + key] 

                for IP in entropies[key]:
                    if IP in last_entropies[key]:
                        delta[key][IP] = entropies[key][IP] - last_entropies[key][IP]
                    else:
                        delta[key][IP] = entropies[key][IP]

            delta_flow_entropies[flow_key] = delta

        else:
            delta_flow_entropies[flow_key] = entropies 
            
        last_key = flow_key
        last_entropies = entropies

def graph_totals(ip=None):

    graph_type = ip.split('.')[2] + "-" + ip.split('.')[3] if ip else 'network'
    
    graph_setups = [
                        ('total_bytes', 'Bytes'), ('total_pkts', 'Packets'), ('total_flows', 'Flows'),
                        ('total_log_bytes', 'logBytes'), ('total_log_pkts', 'logPackets'), ('total_log_flows', 'logFlows'),
                        ('int_ip_entropy', 'IntIPEntropy'), ('ext_ip_entropy', 'ExtIPEntropy'),
                        ('d_int_ip_entropy', 'deltaIntIPEntropy'), ('d_ext_ip_entropy', 'deltaExtIPEntropy'),
                        ('wireless_retries', 'nRetries')
                    ]

    dss = []
    
    for graph in graph_setups:
        dss.append( DS(dsName=graph[0], dsType='GAUGE', heartbeat=900) )
    
    dbl_graph_setups = [ ('ivo_bytes', 'Bytes'), ('ivo_pkts', 'Pkts'), ('ivo_flows', 'Flows')]

    for graph in dbl_graph_setups:
        dss.append( DS(dsName='in_'+graph[0], dsType='GAUGE', heartbeat=900)  )
        dss.append( DS(dsName='out_'+graph[0], dsType='GAUGE', heartbeat=900) )

    myRRD = RRD(rrd_file % graph_type, step=60, ds=dss, rra=rras, start=startTime-60)
    myRRD.create(debug=False)
    
    counter = 0
    for flow_key in keys:
        if ip:
            if ip in flows[flow_key]['internal']:
                in_bytes, out_bytes = (flows[flow_key])['internal'][ip]['in_bytes'], (flows[flow_key])['internal'][ip]['out_bytes']
                in_pkts, out_pkts = (flows[flow_key])['internal'][ip]['in_pkts'], (flows[flow_key])['internal'][ip]['out_pkts']
                in_flows, out_flows = (flows[flow_key])['internal'][ip]['in_flows'], (flows[flow_key])['internal'][ip]['out_flows']
                total_bytes = in_bytes + out_bytes
                total_pkts  = in_pkts + out_pkts
                total_flows = in_flows + out_flows
                log_bytes, log_pkts, log_flows = log(total_bytes, 2), log(total_pkts, 2), log(total_flows, 2)
                nretries = (flows[flow_key])['internal'][ip]['nretries']
            else:
                in_bytes = out_bytes = in_pkts = out_pkts = in_flows = out_flows = 'U'
                total_bytes = total_pkts = total_flows = 'U'
                log_bytes = log_pkts = log_flows = 'U'
                nretries = 'U'
            myRRD.bufferValue(  int(flow_key), 
                                total_bytes, total_pkts, total_flows,
                                log_bytes, log_pkts, log_flows,
                                flow_entropies[flow_key]['external'][ip] if ip in flow_entropies[flow_key]['external'] else 0, 0,
                                delta_flow_entropies[flow_key]['external'][ip] if ip in flow_entropies[flow_key]['external'] else 0, 0,#delta_flow_entropies[flow_key]['internal'][ip],
                                nretries,
                                in_bytes, out_bytes, in_pkts, out_pkts, in_flows, out_flows,
                                )
        else:                
            in_bytes, out_bytes = (flows[flow_key])['in_bytes'], (flows[flow_key])['out_bytes']
            in_pkts, out_pkts = (flows[flow_key])['in_pkts'], (flows[flow_key])['out_pkts']
            in_flows, out_flows = (flows[flow_key])['in_flows'], (flows[flow_key])['out_flows']
            total_bytes = in_bytes + out_bytes
            total_pkts  = in_pkts + out_pkts
            total_flows = in_flows + out_flows
            log_bytes = log(total_bytes, 2) if total_bytes else 0
            log_pkts = log(total_pkts, 2) if total_pkts else 0
            log_flows = log(total_flows, 2) if total_flows else 0
            nretries = (flows[flow_key])['nretries']

            myRRD.bufferValue(  int(flow_key), 
                                total_bytes, total_pkts, total_flows,
                                log_bytes, log_pkts, log_flows,
                                flow_entropies[flow_key]['global_external'], 0,#flow_entropies[flow_key]['global_internal'],
                                delta_flow_entropies[flow_key]['global_external'], 0,#delta_flow_entropies[flow_key]['global_internal'],
                                nretries,
                                in_bytes, out_bytes, in_pkts, out_pkts, in_flows, out_flows,
                                )

        counter += 1
        if counter % 10 == 0:
            myRRD.update()
    
    myRRD.update()
    
    for idx, (feature, label) in enumerate(graph_setups[:-1]):
        
        def1 = DEF(rrdfile=myRRD.filename, vname=label, dsName=dss[idx].name)
        
        vdef1 = VDEF(vname='avg', rpn='%s,AVERAGE' % def1.vname)
        vdef2 = VDEF(vname='min', rpn='%s,MINIMUM' % def1.vname)
        vdef3 = VDEF(vname='max', rpn='%s,MAXIMUM' % def1.vname)
        vdef4 = VDEF(vname='stdev', rpn='%s,STDEV' % def1.vname)
        
        cdef1 = CDEF(vname='slightlyhigh', rpn='%s,avg,stdev,+,GE,%s,UNKN,IF' % (def1.vname, def1.vname))
        cdef2 = CDEF(vname='abnormallyhigh', rpn='%s,avg,stdev,1.5,*,+,GE,%s,UNKN,IF' % (def1.vname, def1.vname))
        cdef3 = CDEF(vname='vhigh', rpn='%s,avg,stdev,2.0,*,+,GE,%s,UNKN,IF' % (def1.vname, def1.vname))
        cdef4 = CDEF(vname='slightlylow', rpn='%s,avg,stdev,-,LE,%s,UNKN,IF' % (def1.vname, def1.vname))
        cdef5 = CDEF(vname='abnormallylow', rpn='%s,avg,stdev,1.5,*,-,LE,%s,UNKN,IF' % (def1.vname, def1.vname))
        cdef6 = CDEF(vname='vlow', rpn='%s,avg,stdev,2.0,*,-,LE,%s,UNKN,IF' % (def1.vname, def1.vname))
        
        area1 = AREA(defObj=def1, color='#00FF00')
        area2 = AREA(defObj=cdef1, color='#FFFF00')
        area3 = AREA(defObj=cdef2, color='#FF9900')
        area4 = AREA(defObj=cdef3, color='#FF0000')
        area5 = AREA(defObj=cdef4, color='#FFFF00')
        area6 = AREA(defObj=cdef4, color='#FF9900')
        area7 = AREA(defObj=cdef4, color='#FF0000')
        
        gprint1 = GPRINT(vdef1, 'Average %.2lf')
        gprint2 = GPRINT(vdef2, 'Min %.2lf')
        gprint3 = GPRINT(vdef3, 'Max %.2lf')
        gprint4 = GPRINT(vdef4, 'Stdev %.2lf')

        g = Graph(graph_file % (graph_type, feature), start=int(keys[0]), end=int(keys[-1]) )
        g.data.extend([def1, vdef1, vdef2, vdef3, vdef4,
                        cdef1, cdef2, cdef3, cdef4, cdef5, cdef6, 
                        area1, area2, area3, area4, area5, area6, area7, 
                        gprint1, gprint2, gprint3, gprint4
                        ])
        if idx > 5:
            g.width = 380
        else:
            g.width = 540
        g.height = 100
        g.write()

    wireless_index = len(graph_setups) - 1
    wireless_feature, wireless_label = graph_setups[wireless_index]
    def1 = DEF(rrdfile=myRRD.filename, vname=wireless_label, dsName=dss[wireless_index].name)
    line1 = LINE(defObj=def1, color='#FF0000')
    g = Graph(graph_file % (graph_type, wireless_feature), start=int(keys[0]), end=int(keys[-1]) )
    g.data.extend([def1, line1])
    g.width = 1800
    g.height = 80
    g.write() 
    
    for idx, (feature, label) in enumerate(dbl_graph_setups):
        def1 = DEF(rrdfile=myRRD.filename, vname=label+'IN', dsName=(dss[len(dss)-(len(dbl_graph_setups)*2)+(idx*2)]).name)
        def2 = DEF(rrdfile=myRRD.filename, vname=label+'OUT', dsName=(dss[len(dss)-(len(dbl_graph_setups)*2)+(idx*2)+1]).name)
        cdef1 = CDEF(vname=label[0]+'IN', rpn='%s' % def1.vname)
        cdef2 = CDEF(vname=label[0]+'OUT', rpn='%s,-1,*' % def2.vname)
        area1 = AREA(defObj=cdef1, color='#FF0000')
        area2 = AREA(defObj=cdef2, color='#00FF00')
        g = Graph(graph_file % (graph_type, feature), start=int(keys[0]), end=int(keys[-1]))
        g.data.extend([def1, def2, cdef1, cdef2, area1, area2])
        g.width = 380
        g.height = 100
        g.write()

#Main

js_file     = 'data.js'

jf = open(js_file, 'w')
jf.write("var times = new Array();\n")
jf.close()

time_index = 0

while True:

    file_str = raw_input("Enter a file time to process: ")

    #Check files exist for all
    if os.path.exists('data/DHCP/dhcp' + file_str + '.db.dh') and os.path.exists('data/FLOWS/Flow' + file_str + '.db.dt') and os.path.exists('data/LINKS/link' + file_str + '.db.lt'):
        print "DHCP, Flows and Link data exists for " + file_str
    else:
        continue

    file_start_timestamp = 0

    for (start_time_count, end_time_count) in [(1,1440),(1,480),(481,960),(961,1440)]:

        FE = FlowExtractor()
        flows, iplist = FE.hwdb_extract(file_str, start_time_count, end_time_count)
        keys = flows.keys()
        keys.sort()

        print "Extracted", len(keys), "minutes of data"

        startTime = int(keys[0])
        
        if not file_start_timestamp:
            file_start_timestamp = str(startTime)

        rrd_file 	= file_start_timestamp + '/rrd/' + str(start_time_count) + '_' + str(end_time_count) + '_%s.rrd'		# Total/IP
        graph_file 	= file_start_timestamp + '/graphs/' + str(start_time_count) + '_' + str(end_time_count) + '_%s_%s.png'	# Total/IP, Feature

        if not os.path.exists(file_start_timestamp):
            os.makedirs(file_start_timestamp + "/rrd")
            os.makedirs(file_start_timestamp + "/graphs")

        calculate_entropies()
        graph_totals()
        print "Done totals"
        jf = open(js_file, 'a')
        
        if (end_time_count - start_time_count) == 1439:
            interval = 24
        else:
            interval = (end_time_count / 60) - 8

        jf.write("times.push({file_time: '" + str(file_str) + "', interval: " + str(interval) + ", unix_time: '" + str(file_start_timestamp) + "', locs: [")
        for ip in iplist:
            jf.write("'" + str(ip) + "', ")

        jf.write("'network']});\n")
        jf.close()
        print "Appended to js file"
        for ip in iplist:
            if ip == '192.168.1.1':
              continue
            graph_totals(ip)
            print " - Processed %s" % str(ip)
