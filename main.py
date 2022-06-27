g=b'hey!! how are you?'
f='www.google.com'
e='flags'
d='Use for experimentation and testing'
V='.'
U=Exception
T=str
O='checksum'
N=len
M=hex
L='\n'
K='{}({})'
H=''
E=int
D=print
A='Unassigned'
W=['HOPOPT','ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts',H,'CFTP',H,'SAT-EXPAK','KRYPTOLAN','RVD','IPPC',H,'SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP / IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP',H,'GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM',H,'L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet',A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,d,d,'Reserved']
F='\x1b[0m'
R='\x1b[0;30;41m'
P='\x1b[0;30;42m'
X='\x1b[0;30;46m'
import sys as Q,socket as B,os,struct as I
os.system(H)
def Y(raw_data):B=raw_data;C,H,J,L,N,P,A,D,Q,R=I.unpack('!BBHHHBBH4s4s',B[:20]);S=f"{C:08b}"[:4];U=f"{C:08b}"[4:];F=V.join((T(E(A))for A in Q));G=V.join((T(E(A))for A in R));X=B[20:];Y={'version':E(S,2),'header length':E(U,2),'tos (type of service)':H,'total length':J,'identification':L,e:N,'ttl (time to live)':P,'protocol':K.format(A,W[A]),O:K.format(M(D),D),'source address':F,'destination address':G};return Y,X,A,F,G
def Z(proto,raw_data):
	g='destination port';f='source port';d='type';F=proto;B=raw_data
	if F==1:C,Q,A,R,D=I.unpack('!BBHHH',B[:8]);G=B[8:];H={d:C,'code':Q,O:K.format(M(A),A),'identifier':R,'sequence number':D}
	if F==99999:C,J,A,S,D,U,W=I.unpack('!BBH4sBBH',B[:12]);G=B[12:];H={d:f"{C:8b}"[:3],'type1':f"{C:8b}"[3:4],'type2':f"{C:8b}"[4:],'max res. time':J,O:K.format(M(A),A),'group address':V.join((T(E(A))for A in S)),'seq':D,'QQIC':U,'number of sources':W}
	elif F==17:L,N,X,A=I.unpack('!HHHH',B[:8]);G=B[8:];H={f:L,g:N,'length':X,O:K.format(M(A),A)}
	elif F==6:L,N,D,Y,P,Z,A,a=I.unpack('!HHIIHHHH',B[:20]);G=B[20:];b=f"{P:16b}"[:4];J=f"{P:16b}"[4:7];c=f"{P:16b}"[7:];H={f:L,g:N,'sequece number':D,'acknowledge number':Y,'data offset':E(b,2),'reserved':J,e:c,'windows size':Z,O:K.format(M(A),A),'urgent pointer':a}
	else:return False
	return H,G
def a(binary):
	A=binary
	if N(A)<8:A=a('0'+A)
	return A
class J(U):
	def __init__(A,message=L+X+' Filtered packet '+F):A.message=message;super().__init__(A.message)
def h(h=f,p=80):A=B.socket(B.AF_INET,B.SOCK_DGRAM);A.sendto(g,(h,p));A.close()
def i():A=B.socket(B.AF_INET,B.SOCK_STREAM);A.connect((f,80));A.send(g);A.close()
def b():
	i=' -------------------- end ------------------- ';X='win32';O=None
	try:
		M=B.getaddrinfo(B.gethostname(),port=0,type=3);S=M[N(M)-1][N(M[N(M)-1])-1]
		if Q.platform==X:A=B.socket(B.AF_INET,B.SOCK_RAW,B.IPPROTO_IP);A.bind(S);A.setsockopt(B.IPPROTO_IP,B.IP_HDRINCL,1);A.ioctl(B.SIO_RCVALL,B.RCVALL_ON)
		else:A=B.socket(B.AF_PACKETS,B.SOCK_RAW,B.IPPROTO_IP);A.bind(S)
		a,j=A.recvfrom(65565);b,c,T,V,W=Y(a)
		if C.IP is not O and(C.IP!=V and C.IP!=W):raise J()
		if C.SIP is not O and C.SIP!=V:raise J()
		if C.DIP is not O and C.DIP!=W:raise J()
		if C.Protocol is not O and E(C.Protocol)!=T:raise J()
		D(L+P+' ----------------- IP Layer ----------------- '+F)
		for (I,K) in b.items():D(f"{I:25}: {K}")
		D(L+P+' ------------- transport proto -------------- '+F);G=Z(T,c)
		if G:
			d=G[0]
			for (I,K) in d.items():D(f"{I:25}: {K}")
		else:raise U('protocol disection not supported')
		D(L+P+' ----------------- payload ------------------ '+F)
		if G:
			e=H.join((chr(E(A))for A in G[1]));f={'len':N(G[1]),'raw':G[1],'parsed':e}
			for (I,K) in f.items():D(f"{I:25}: {K}")
		D(L+R+i+F)
		if Q.platform==X:A.ioctl(B.SIO_RCVALL,B.RCVALL_OFF)
		A.close()
	except J as g:D(g)
	except U as h:
		D(h);D(L+R+i+F)
		if Q.platform==X:A.ioctl(B.SIO_RCVALL,B.RCVALL_OFF)
		A.close()
import argparse as c
G=c.ArgumentParser()
G.add_argument('-n','--Number',help='Number of packets to capture')
G.add_argument('-ip','--IP',help='IP to filter')
G.add_argument('-sip','--SIP',help='Source IP to filter')
G.add_argument('-dip','--DIP',help='Destination IP to filter')
G.add_argument('-proto','--Protocol',help='Protocol to filter')
C=G.parse_args()
if C.Number:S=E(C.Number)
else:S=0x8ac7230489e7ffff
for j in range(S):b()
