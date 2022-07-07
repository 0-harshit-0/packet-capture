_I=b'hey!! how are you?'
_H='www.google.com'
_G=' Filtered packet '
_F='Use for experimentation and testing'
_E='utf-8'
_D='checksum'
_C='{}({})'
_B='\n'
_A='Unassigned'
protocol_map=['HOPOPT','ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP / IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet',_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_F,_F,'Reserved']
END='\x1b[0m'
REDBG='\x1b[0;30;41m'
GREENBG='\x1b[0;30;42m'
BLUEBG='\x1b[0;30;46m'
import sys,socket,os,struct
os.system('')
def ethernet_head_parse(raw_data):dest,src,prototype=struct.unpack('!6s6sH',raw_data[:14]);dest_mac=dest.hex();src_mac=src.hex();proto=prototype;data=raw_data[14:];parsed={'dest_mac':':'.join([dest_mac[i:i+2]for i in range(0,len(dest_mac),2)]),'src_mac':':'.join([src_mac[i:i+2]for i in range(0,len(src_mac),2)]),'proto':_C.format(hex(proto),proto)};return parsed,data
def ipv4_head(raw_data):version_header_length,tos,total_length,identification,flags,ttl,proto,checksum,src,target=struct.unpack('!BBHHHBBH4s4s',raw_data[:20]);version=f"{version_header_length:08b}"[:4];header_length=f"{version_header_length:08b}"[4:];s='.'.join((str(int(x))for x in src));d='.'.join((str(int(x))for x in target));data=raw_data[20:];networkLayer={'version':int(version,2),'header length':int(header_length,2),'tos (type of service)':tos,'total length':total_length,'identification':identification,'flags':flags,'ttl (time to live)':ttl,'protocol':_C.format(proto,protocol_map[proto]),_D:_C.format(hex(checksum),checksum),'source address':s,'destination address':d};return networkLayer,data,proto,s,d
def transport_parse(proto,raw_data):
	C='destination port';B='source port';A='type'
	if proto==1:typ,code,checksum,identifier,seq=struct.unpack('!BBHHH',raw_data[:8]);data=raw_data[8:];parsed={A:typ,'code':code,_D:_C.format(hex(checksum),checksum),'identifier':identifier,'sequence number':seq}
	if proto==99999:typ,res,checksum,group,seq,qic,source=struct.unpack('!BBH4sBBH',raw_data[:12]);data=raw_data[12:];parsed={A:f"{typ:8b}"[:3],'type1':f"{typ:8b}"[3:4],'type2':f"{typ:8b}"[4:],'max res. time':res,_D:_C.format(hex(checksum),checksum),'group address':'.'.join((str(int(x))for x in group)),'seq':seq,'QQIC':qic,'number of sources':source}
	elif proto==17:src_port,dest_port,length,checksum=struct.unpack('!HHHH',raw_data[:8]);data=raw_data[8:];parsed={B:src_port,C:dest_port,'length':length,_D:_C.format(hex(checksum),checksum)}
	elif proto==6:src_port,dest_port,seq,ack,data_flag,ws,checksum,pointer=struct.unpack('!HHIIHHHH',raw_data[:20]);data=raw_data[20:];off=f"{data_flag:16b}"[:4];res=f"{data_flag:16b}"[4:7];flags=f"{data_flag:16b}"[7:];parsed={B:src_port,C:dest_port,'sequece number':seq,'acknowledge number':ack,'data offset':int(off,2),'reserved':res,'flags':flags,'windows size':ws,_D:_C.format(hex(checksum),checksum),'urgent pointer':pointer}
	else:return False
	return parsed,data
def makeCompleteBinary(binary):
	if len(binary)<8:binary=makeCompleteBinary('0'+binary)
	return binary
class Filter(Exception):
	def __init__(self,message=_B+BLUEBG+_G+END):self.message=message;super().__init__(self.message)
def testUDP(h=_H,p=80):so=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);so.sendto(_I,(h,p));so.close()
def testTCP():so=socket.socket(socket.AF_INET,socket.SOCK_STREAM);so.connect((_H,80));so.send(_I);so.close()
from ctypes import *
from libpcap import *
class Filter(Exception):
	def __init__(self,message=_B+BLUEBG+_G+END):self.message=message;super().__init__(self.message)
def packet(pkt_data,pkt_len):
	A=' -------------------- end ------------------- '
	try:
		print(_B+GREENBG+' ----------------- Data Layer ----------------- '+END);st=string_at(pkt_data,pkt_len);eth,data=ethernet_head_parse(st)
		for (label,value) in eth.items():print(f"{label:25}: {value}")
		print(_B+GREENBG+' ---------------- Network Layer --------------- '+END);show,d,pro,src,dst=ipv4_head(data)
		for (label,value) in show.items():print(f"{label:25}: {value}")
		print(_B+GREENBG+' -------------- Transport Layer --------------- '+END);transport=transport_parse(pro,d)
		if transport:
			transportLayer=transport[0]
			for (label,value) in transportLayer.items():print(f"{label:25}: {value}")
		else:raise Exception('protocol not supported')
		print(_B+GREENBG+' ------------------ Payload ------------------ '+END)
		if transport:
			dataArr=''.join((chr(int(x))for x in transport[1]));chunk={'len':len(transport[1]),'raw':transport[1],'parsed':dataArr}
			for (label,value) in chunk.items():print(f"{label:25}: {value}")
		print(_B+REDBG+A+END)
	except Exception as e:print(e);print(_B+REDBG+A+END)
	return 1
alldevs=pointer(pcap_if())
fp=pointer(pcap_if())
errbuf=c_char_p(bytes(PCAP_ERRBUF_SIZE))
findalldevs(alldevs,errbuf)
temp=alldevs.contents
while temp:
	if'Intel'in temp.description.decode(_E):dev=c_char_p(temp.name);break
	temp=temp.next.contents
print('device:',temp.name.decode(_E),temp.description.decode(_E))
fp=open(dev,100,PCAP_OPENFLAG_PROMISCUOUS,20,None,errbuf)
header=pointer(pkthdr())
pkt_data=pointer(c_ubyte())
freealldevs(alldevs)
def main():
	global till;res=next_ex(fp,header,pkt_data)
	while res>=0 and till>0:
		if res==0:res=next_ex(fp,header,pkt_data);continue
		till-=1;packet(pkt_data,header.contents.len);print(_B);res=next_ex(fp,header,pkt_data)
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('-n','--Number',help='Number of packets to capture')
parser.add_argument('-ip','--IP',help='IP to filter')
parser.add_argument('-sip','--SIP',help='Source IP to filter')
parser.add_argument('-dip','--DIP',help='Destination IP to filter')
parser.add_argument('-proto','--Protocol',help='Protocol to filter')
args=parser.parse_args()
if args.Number:till=int(args.Number)
else:till=0x8ac7230489e7ffff
main()
