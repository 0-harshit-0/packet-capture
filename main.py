V='flags'
H='Use for experimentation and testing'
U=range
T=str
M='checksum'
L=hex
K='{}({})'
J=len
G=''
D=print
C=int
A='Unassigned'
import sys,socket as B,struct as E
Q=['HOPOPT','ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II','PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2','LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP','IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP','AH','I-NLSP','SwIPe','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts',G,'CFTP',G,'SAT-EXPAK','KRYPTOLAN','RVD','IPPC',G,'SAT-MON','VISA','IPCU','CPNX','CPHB','WSN','PVP','BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP / IPTM','NSFNET-IGP','DGP','TCF','EIGRP','OSPF','Sprite-RPC','LARP','MTP','AX.25','OS','MICP','SCC-SP','ETHERIP','ENCAP',G,'GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer','IPX-in-IP','VRRP','PGM',G,'L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM','PTP','IS-IS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE','Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC','Ethernet',A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,H,H,'Reserved']
def R(raw_data):A=raw_data;B,C,D,F,G,H,I,J,K,L=E.unpack('!BBHHHBBH4s4s',A[:20]);M=f"{B:08b}"[:4];N=f"{B:08b}"[4:];O=A[20:];return M,N,C,D,F,G,H,I,J,K,L,O
def S(proto,raw_data):
	a='destination port';Z='source port';D=proto;B=raw_data
	if D==1:O,P,A,Q,F=E.unpack('!BBHHH',B[:8]);G=B[8:];H={'type':O,'code':P,M:K.format(L(A),A),'identifier':Q,'sequence number':F}
	elif D==17:I,J,R,A=E.unpack('!HHHH',B[:8]);G=B[8:];H={Z:I,a:J,'length':R,M:K.format(L(A),A)}
	elif D==6:I,J,F,S,N,T,A,U=E.unpack('!HHIIHHHH',B[:20]);G=B[20:];W=f"{N:16b}"[:4];X=f"{N:16b}"[4:7];Y=f"{N:16b}"[7:];H={Z:I,a:J,'sequece number':F,'acknowledge number':S,'data offset':C(W,2),'reserved':X,V:Y,'windows size':T,M:K.format(L(A),A),'urgent pointer':U}
	else:return False
	return H,G
def N(binary):
	A=binary
	if J(A)<8:A=N('0'+A)
	return A
def F():
	c=' ';b='.';d=B.gethostbyname(B.gethostname());E=B.socket(B.AF_INET,B.SOCK_RAW,B.IPPROTO_IP);E.bind(('192.168.29.59',0));E.setsockopt(B.IPPROTO_IP,B.IP_HDRINCL,1);E.ioctl(B.SIO_RCVALL,B.RCVALL_ON);W,e=E.recvfrom(65565);D('\n --------------- IP Packet ---------------');A=R(W)
	if J(sys.argv)>1 and C(sys.argv[1])!=C(A[7]):return 0
	X={'version':C(A[0],2),'header length':C(A[1],2),'tos (type of service)':A[2],'total length':A[3],'identification':A[4],V:A[5],'ttl (time to live)':A[6],'protocol':K.format(A[7],Q[A[7]]),M:K.format(L(A[8]),A[8]),'source address':b.join((T(C(B,16))for B in[A[9].hex()[B:B+2]for B in U(0,J(A[9].hex()),2)])),'destination address':b.join((T(C(B,16))for B in[A[10].hex()[B:B+2]for B in U(0,J(A[10].hex()),2)]))}
	for (H,I) in X.items():D(f"{H:25}: {I}")
	D('\n --------------- transport ---------------');F=S(A[7],A[11])
	if F:
		O=F[0]
		for (H,I) in O.items():D(f"{H:25}: {I}")
	else:O='protocol not available'
	D('\n --------------- data ---------------')
	if F:
		Y=c.join((format(C(A),'b')for A in F[1])).split(c);P=G
		for Z in Y:P+=chr(C(N(Z),2))
		a={'len':J(F[1]),'raw':F[1],'parsed':P}
		for (H,I) in a.items():D(f"{H:25}: {I}")
	D('\n --------------- end ---------------');E.ioctl(B.SIO_RCVALL,B.RCVALL_OFF);E.close()
while True:F()
