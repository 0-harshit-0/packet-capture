_Q='dump.pcap'
_P=b'hey!! how are you?'
_O='www.google.com'
_N=' Filtered packet '
_M='flags'
_L='Use for experimentation and testing'
_K='IPv6'
_J=False
_I='type'
_H=None
_G=':'
_F='checksum'
_E='.'
_D='utf-8'
_C='{}({})'
_B='\n'
_A='Unassigned'
protocol_map=['HOPOPT','ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL',_K,'SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts','','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP / IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet',_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_A,_L,_L,'Reserved']
type_map_rev={'0x800':'IPv4','0x806':'ARP','0x86dd':_K}
import socket,struct,os
os.system('')
END='\x1b[0m'
REDBG='\x1b[0;30;41m'
GREENBG='\x1b[0;30;42m'
BLUEBG='\x1b[0;30;46m'
ORANGEBG='\x1b[0;30;43m'
def ethernet_head_parse(raw_data):dest,src,prototype=struct.unpack('!6s6sH',raw_data[:14]);dest_mac=dest.hex();src_mac=src.hex();proto=prototype;data=raw_data[14:];parsed={'dest_mac':_G.join([dest_mac[i:i+2]for i in range(0,len(dest_mac),2)]),'src_mac':_G.join([src_mac[i:i+2]for i in range(0,len(src_mac),2)]),_I:_C.format(hex(proto),type_map_rev[hex(proto)])};return parsed,data
def arp_head(raw_data):htype,ptype,hsize,psize,opcode,smac,sipa,tmac,tipa=struct.unpack('!HHBBH6s4s6s4s',raw_data[:28]);smac=smac.hex();tmac=tmac.hex();networkLayer={'Hardware type':htype,'Protocol type':ptype,'Hardware length':hsize,'Protocol length':psize,'Operation':opcode,'Sender Hardware Address':_G.join([smac[i:i+2]for i in range(0,len(smac),2)]),'Sender IP':_E.join((str(int(x))for x in sipa)),'Target Hardware Address':_G.join([tmac[i:i+2]for i in range(0,len(tmac),2)]),'Target IP':_E.join((str(int(x))for x in tipa))};return networkLayer,raw_data[28:]
def ipv4_head(raw_data):version_header_length,tos,total_length,identification,flags,ttl,proto,checksum,src,target=struct.unpack('!BBHHHBBH4s4s',raw_data[:20]);version=f"{version_header_length:08b}"[:4];header_length=f"{version_header_length:08b}"[4:];s=_E.join((str(int(x))for x in src));d=_E.join((str(int(x))for x in target));data=raw_data[20:];networkLayer={'version':int(version,2),'header length':int(header_length,2),'tos (type of service)':tos,'total length':total_length,'identification':identification,_M:flags,'ttl (time to live)':ttl,'protocol':_C.format(proto,protocol_map[proto]),_F:_C.format(hex(checksum),checksum),'source address':s,'destination address':d};return networkLayer,data,proto,s,d
def transport_parse(proto,raw_data):
    B='destination port';A='source port'
    if proto==1:typ,code,checksum,identifier,seq=struct.unpack('!BBHHH',raw_data[:8]);data=raw_data[8:];parsed={_I:typ,'code':code,_F:_C.format(hex(checksum),checksum),'identifier':identifier,'sequence number':seq}
    if proto==99999:typ,res,checksum,group,seq,qic,source=struct.unpack('!BBH4sBBH',raw_data[:12]);data=raw_data[12:];parsed={_I:f"{typ:8b}"[:3],'type1':f"{typ:8b}"[3:4],'type2':f"{typ:8b}"[4:],'max res. time':res,_F:_C.format(hex(checksum),checksum),'group address':_E.join((str(int(x))for x in group)),'seq':seq,'QQIC':qic,'number of sources':source}
    elif proto==17:src_port,dest_port,length,checksum=struct.unpack('!HHHH',raw_data[:8]);data=raw_data[8:];parsed={A:src_port,B:dest_port,'length':length,_F:_C.format(hex(checksum),checksum)}
    elif proto==6:src_port,dest_port,seq,ack,data_flag,ws,checksum,pointer=struct.unpack('!HHIIHHHH',raw_data[:20]);data=raw_data[20:];off=f"{data_flag:16b}"[:4];res=f"{data_flag:16b}"[4:7];flags=f"{data_flag:16b}"[7:];parsed={A:src_port,B:dest_port,'sequece number':seq,'acknowledge number':ack,'data offset':int(off,2),'reserved':res,_M:flags,'windows size':ws,_F:_C.format(hex(checksum),checksum),'urgent pointer':pointer}
    else:return _J
    return parsed,data
def makeCompleteBinary(binary):
    if len(binary)<8:binary=makeCompleteBinary('0'+binary)
    return binary
class Filter(Exception):
    def __init__(self,message=_B+BLUEBG+_N+END):self.message=message;super().__init__(self.message)
def testUDP(h=_O,p=80):so=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);so.sendto(_P,(h,p));so.close()
def testTCP():so=socket.socket(socket.AF_INET,socket.SOCK_STREAM);so.connect((_O,80));so.send(_P);so.close()
from ctypes import *
from libpcap import *
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('-n','--Number',help='Number of packets to capture/dump/display',type=int,default=99999999999999999)
parser.add_argument('-t','--Type',help='Type of packet',type=str,default='ip')
parser.add_argument('-d','--Dump',help='Dump the packets to a file instead of displaying',default=_J,nargs='?',const=_Q)
parser.add_argument('-od','--OpenDump',help='Open and read the dump file',default=_J,nargs='?',const=_Q)
parser.add_argument('-dip','--DIP',help='Destination IP to filter')
parser.add_argument('-sip','--SIP',help='Source IP to filter')
parser.add_argument('-ip','--IP',help='IP to filter')
parser.add_argument('-mac','--MAC',help='MAC to filter')
parser.add_argument('-proto','--Protocol',help='Protocol to filter')
args=parser.parse_args()
till=args.Number
class Filter(Exception):
    def __init__(self,message=_B+BLUEBG+_N+END):self.message=message;super().__init__(self.message)
def packet(pkt_data,pkt_len):
    A=' -------------------- End ------------------- '
    try:
        print(_B+GREENBG+' ----------------- Data Layer ----------------- '+END);st=string_at(pkt_data,pkt_len);eth,data=ethernet_head_parse(st)
        for (label,value) in eth.items():print(f"{label:25}: {value}")
        print(_B+GREENBG+' ---------------- Network Layer --------------- '+END)
        if args.Type=='ip':show,d,pro,src,dst=ipv4_head(data)
        elif args.Type=='arp':show,d=arp_head(data)
        for (label,value) in show.items():print(f"{label:25}: {value}")
        if len(d)==0:raise Exception('')
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
source=c_char_p(bytes(PCAP_BUF_SIZE))
fcode=pointer(bpf_program())
findalldevs(alldevs,errbuf)
temp=alldevs.contents
devices=[]
while temp.next:devices.append(temp);temp=temp.next.contents
for i in range(len(devices)):print(i,devices[i].description.decode(_D))
div=input('\nselect the device/interface to start capture: ')
dev=c_char_p(devices[int(div)].name)
print(_B+BLUEBG+' starting capturing on {} {} '.format(devices[int(div)].name.decode(_D),devices[int(div)].description.decode(_D))+END)
netp=bpf_u_int32()
maskp=bpf_u_int32()
ret=lookupnet(dev,netp,maskp,errbuf)
if args.OpenDump:createsrcstr(source,PCAP_SRC_FILE,_H,_H,args.OpenDump.encode(_D),errbuf);fp=open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,20,_H,errbuf)
else:fp=open(dev,65536,PCAP_OPENFLAG_PROMISCUOUS,20,_H,errbuf)
fil=''
if args.Type:fil+=args.Type
if args.Protocol:fil+=' and proto {}'.format(args.Protocol)
if args.MAC:fil+=' and ether host {}'.format(args.MAC)
if args.DIP:fil+=' and dst host {}'.format(args.DIP)
if args.SIP:fil+=' and src host {}'.format(args.SIP)
if args.IP:fil+=' and host {}'.format(args.IP)
compile(fp,fcode,fil.encode(_D),1,maskp)
setfilter(fp,fcode)
header=pointer(pkthdr())
pkt_data=pointer(c_ubyte())
freealldevs(alldevs)
def main():
    global till;res=next_ex(fp,header,pkt_data)
    while res>=0 and till>0:
        if res==0:res=next_ex(fp,header,pkt_data);continue
        packet(pkt_data,header.contents.len);print(_B);res=next_ex(fp,header,pkt_data);till-=1
def dumpmain():
    global till;dumpfile=dump_open(fp,args.Dump.encode(_D));res=next_ex(fp,header,pkt_data)
    while res>=0 and till>0:
        if res==0:res=next_ex(fp,header,pkt_data);continue
        dump(cast(dumpfile,POINTER(c_ubyte)),header,pkt_data);print(_B+ORANGEBG+' Packet Dumped '+END);res=next_ex(fp,header,pkt_data);till-=1
if args.Dump:dumpmain()
else:main()
