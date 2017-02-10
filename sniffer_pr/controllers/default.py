import socket
from struct import *
import datetime
import pcapy,time
import sys
import thread
import threading
import subprocess,signal
from pcapy import open_live, findalldevs, PcapError
import time
#from pcapy import findalldevs,open_live
#from impacket import ImpactDecoder, ImpactPacket
#from impacket.ImpactDecoder import *




c_tcp = 0
c_udp = 0
c_icmp = 0
packets = []



# this is the main function of the application , here the user gives the input interface on which the user wants to capture
# this function calls the "start" function that  captures the data.
# output : selected interface sent to start function

def index():
    #sniffer()\
    devices = pcapy.findalldevs()
    form = SQLFORM.factory(Field('interface', requires=IS_IN_SET(tuple(devices)),widget=SQLFORM.widgets.radio.widget))
    if form.process().accepted:
        redirect(URL('start',vars = {'interface':form.vars.interface}))
    return locals()


# this is the actual place where the capture takes place 
# input : interface
# func_calls : parse_packet , sends a packet 
# output : total number of packets of a particular type , all packets , total no.of packets of a type in a particular time.


def sniffer(interf):
	
        session._unlock(response)
	graph_data = list()
        session.b = list()
	
    	global packets
    	#pc = pcap.pcap()
	promiscuous = True
	cap = pcapy.open_live(interf , 65536 , promiscuous ,100)

	#packet_limit = -1 # infinite
    	#cap.loop(packet_limit, parse_packet)
	#count=9
	t1 = (str(time.time()).split('.'))[0]
    	tcp = 0
    	udp = 0
    	icmp = 0
	count=0
	flag=0
	while flag< 20:
            	t2 = (str(time.time()).split('.'))[0]
            	try:
			#print "difference is :" + str(int(t2) -int(t1))
			if (int(t2) -int(t1) >= 1):
				count = count + 1
				temp = [(count) , tcp , udp , icmp]
				graph_data.append(temp)
                		session.b = graph_data

                        	print len(session.b)    
				print "***************************************"
                		print str(tcp) + ',' + str(udp) + ',' + str(icmp)
				t1 = (str(time.time()).split('.'))[0]
				global c_tcp
				c_tcp = c_tcp + tcp
				global c_udp				
				c_udp = c_udp + udp
				global c_icmp				
				c_icmp = c_icmp + icmp
                    		session.tcp = c_tcp
                    		session.udp = c_udp
                    		session.icmp = c_icmp
				tcp = 0
				udp = 0
				icmp = 0

			else:
				#print "chose to capture packet"
				(header,packet) = cap.next()
				
				#count = count+1
                	        typ = parse_packet(header,packet)
              			#print "current packet type :" + str(typ)
				if typ== 'tcp':
					tcp=tcp+1
				if typ== 'udp':
					udp=udp+1
				if typ== 'icmp':
					icmp=icmp+1				
				#print "this packets t1 and t2 :" + str(t2) + ',' + str(t1)
			
			
                		flag = flag+1    	
                except socket.timeout:
			#print "pass"
                        pass
		
	#print packets
    	session.a = packets
        

	print str(tcp) + ',' + str(udp) + ',' + str(icmp)

        return locals()

    
# function used for parsing the etheret header
#input : ethernet header
#output : parsed header


def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

#function to parse a packet
# input : packet
# output : complete details of all headers present in a packet like: ip_addr , mac_addr etc.
def parse_packet(hdr,packet) :
	global packets
    	typ = 'none'
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	#print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
        dest_mac = str(eth_addr(packet[0:6]))
        src_mac =  str(eth_addr(packet[6:12]))
	#Parse IP packets, IP Protocol number = 8
    	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);

		#print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        	string = dest_mac + ',' + src_mac + ',' + str(version) + ',' + str(ihl) + ',' + str(ttl) + ',' + str(protocol) + ',' + str(s_addr) + ',' + str(d_addr)
		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			#now unpack them :)
			tcph = unpack('!HHLLBBHHH' , tcp_header)
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

			string = string + ',' +  str(source_port) + ', ' + str(dest_port) + ' , ' + str(sequence) + ' , ' + str(acknowledgement) + ' , ' + str(tcph_length)
            		typ = 'tcp'
			h_size = eth_length + iph_length + tcph_length * 4
			data_size = len(packet) - h_size
			#get data from the packet
			data = packet[h_size:]
#			print 'Data : ' + data

		#ICMP Packets
		elif protocol == 1 :
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]

			#now unpack them :)
			icmph = unpack('!BBH' , icmp_header)
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			#print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
			
			string = string + ',' + str(icmp_type) + ',' + str(code) + ',' + str(checksum)
            		typ = 'icmp'
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
			#get data from the packet
			data = packet[h_size:]
#			print 'Data : ' + data

		#UDP packets
		elif protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]

			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

			string = string + ', ' + str(source_port) + ',' + str(dest_port) + ',' + str(length) + ',' + str(checksum)			
            		typ = 'udp'
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
			#get data from the packet
			data = packet[h_size:]
#			print 'Data : ' + data

		#some other IP packet like IGMP
		else :
			print 'Protocol other than TCP/UDP/ICMP'
		packets.append(string)

    	else:
    		print "none"

        return typ

    
# this function is the one that calls the sniffer thread
# later it is redirected to a chart function
def start() :
    interface = request.vars.interface
    print "**********************"+interface + "*************"
    thread.start_new_thread(sniffer,(interface,))
    t1 = threading.Thread(target=sniffer, args=(interface,))
    t1.start()
    t1.join()
    
    print "workng"
    redirect(URL('chart',vars = {}))
    return locals()





def snif():
   
    d = session.b
    return locals()

def show_pack():
   

    print "showing_packets"
    
    x = session.a
    
    return locals()
def getdata():
    session._unlock(response)
    import json
    d = session.b
    #print session.b
    return json.dumps(d)

def chart():
    x = session.tcp
    b = session.udp
    c = session.icmp
    dados_chart="[{name: 'tcp', y: " + str(x) +" },{name: 'udp', y:" + str(b) + "},{name: 'icmp', y: " + str(c) + " }]" #Change this dynamically
    dados_map={}
    dados_map["dados"]=dados_chart
    chart="""
    <script type="text/javascript">
    Highcharts.setOptions({
        lang:{
        downloadJPEG: "Download em imagem JPG",
        downloadPDF: "Download em documento PDF",
        downloadPNG: "Download em imagem PNG",
        downloadSVG: "Download em vetor SVG",
        loading: "Loading...",
        noData: "No data",
        printChart: "Graph",
        }
        });

            // Build the chart
            $('#chart').highcharts({
                chart: {
                    plotBackgroundColor: null,
                    plotBorderWidth: null,
                    plotShadow: false,
                    type: 'pie'
                },
                title: {
                    text: 'Analysis'
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.percentage:.1f}%%</b>'
        },
        plotOptions: {
            pie: {
                allowPointSelect: true,
                cursor: 'pointer',
                dataLabels: {
                    enabled: false
                },
                showInLegend: true
            }
        },
        credits:{enabled:false},
        series: [{
            name: 'percentage',
            colorByPoint: true,
                data: %(dados)s
                }]
            });
    </script>
    """ %dados_map
    return dict(chart=XML(chart))
def table():
    k = session.a
    l=list()
    #print k
    for entry in k:
        entry_list = entry.split(',')
        if entry_list[5]=='17':
            entry_list[5]='udp'
        if entry_list[5]=='6':
            entry_list[5]='tcp'
        if entry_list[5]=='1':
            entry_list[5]='icmp'
        temp = list()
        temp.append(entry_list[0])
        temp.append(entry_list[1])
        temp.append(entry_list[5])
        temp.append(entry_list[6])
        temp.append(entry_list[7])
        l.append(temp)

    return locals()
