#url i used :   https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref
# This script runs on Python 3


import binascii
import socket, threading
import sys, getopt
from struct import pack



def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'open'
        TCPsock.close()
    except:
        output[port_number] = 'closed'
    return



def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s = s + w
    # s = 0x119cc
    s = (s >> 16) + (s & 0xffff)
    # s = 0x19cd
    s = ~s & 0xffff
    # s = 0xe632
    return s


class TCPpacket:
    def __init__(self, source_ip, dest_ip, source_port, dest_port, method):
        # ------------------------assemble ip header--------------
        self.version = 4
        self.header_length = 5
        self.version_ihl = (self.version << 4) + self.header_length
        self.type_of_service = 0
        self.total_length = 20 + 20
        self.identification = 54321
        self.frag_flag = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.header_checksum = 10
        self.source_ip = socket.inet_aton(source_ip)
        self.dest_ip = socket.inet_aton(dest_ip)
        self.ip_header = pack('!BBHHHBBH4s4s', self.version_ihl, self.type_of_service, self.total_length,
                              self.identification, self.frag_flag, self.ttl, self.protocol,
                              self.header_checksum, self.source_ip, self.dest_ip)
        # --------------------------------------Assemble TCP header----------------------------------
        self.source_port = source_port
        self.dest_port = dest_port
        self.sequence_number = 0
        self.acknowledgment_number = 0
        self.offser_reserved = (5 << 4) + 0
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.psh = 0
        self.rst = 0
        if method == 0:
            self.ack = 0
            self.syn = 1
            self.fin = 0
        if method == 1 or method==3:  #1 is ack scan and 3 is tcp windows scan
            self.ack = 1
            self.syn = 0
            self.fin = 0
        if method == 2:
            self.ack = 0
            self.syn = 0
            self.fin = 1
        if method == 4:
            self.ack = 0
            self.syn = 0
            self.fin = 0
            self.rst = 1
        self.tcp_flags = (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + \
                         (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        self.windows_size = 1024  # max allowed size    socket.htons(5840)
        self.checksum = 0
        self.urgent_pointer = 0
        self.tcp_header = pack('!HHLLBBHHH', self.source_port, self.dest_port, self.sequence_number,
                               self.acknowledgment_number, self.offser_reserved, self.tcp_flags,
                               self.windows_size, self.checksum, self.urgent_pointer)
        # ----------------------------Calculation TCP Checksum-----------------------------------
        self.pclaceholder = 0
        self.tcp_length = len(self.tcp_header)
        self.tmp = pack('!4s4sBBH', self.source_ip, self.dest_ip, self.pclaceholder, self.protocol,
                        self.tcp_length)
        self.tmp = self.tmp + self.tcp_header
        self.checksum = checksum(self.tmp)
        # ----------------------------Reassemble TCP header---------------------------------
        self.tcp_header = pack('!HHLLBBHHH', self.source_port, self.dest_port, self.sequence_number,
                               self.acknowledgment_number, self.offser_reserved, self.tcp_flags,
                               self.windows_size, self.checksum, self.urgent_pointer)
        self.packet = self.ip_header + self.tcp_header

    def send_packet(self,ip,delay):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(delay)
        s.sendto(self.packet, (ip, 0))

        data = s.recv(1024)
        s.close()
        return data


# could work with e.g. struct.unpack() here
# however, lazy PoC (012 = [SYN ACK]), therefore:
#and (004=[rst])
#url i use to response :   https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref
def check_if_open(port, response,method,outputs):
    cont = binascii.hexlify(response)
    if(method==0 ):#syn scan
        if cont[65:68] == b"012": # we receve a syn/ack response
            #print("Port " + str(port) + " is: open")
            outputs[port]='open'
        elif cont[65:68]== b'004':                              # b"004" :we receve a rst response
            #print("Port " + str(port) + " is: closed")
            outputs[port] = 'closed'
        else:    #icmp eror (type3,code 1,2,3,9,10 or 13)
            #print("Port " + str(port) + " is: filtered")
            outputs[port] = 'filtered'

    elif(method==2):#fin scan
        if cont[65:68] == b'004':  # b"004" :we receve a rst response
            #print("Port " + str(port) + " is: closed")
            outputs[port] = 'closed'
        else: #icmp eror (type3,code 1,2,3,9,10 or 13)
            #print("Port " + str(port) + " is: filetered")
            outputs[port] = 'filtered'

    elif(method==1): #ack scan
        if cont[65:68]== b'004':                              # b"004" :we receve a rst response
            #print("Port " + str(port) + " is: unfiltered")
            outputs[port] = 'unfiltered'
        else:                                 # icmp eror (type3,code 1,2,3,9,10 or 13)
            #print("Port " + str(port) + " is: filetered")
            outputs[port] = 'filtered'

    elif(method==3) :  #method 3   windows scan
        if cont[65:68]== b'004':                 # b"004" :we receve a rst response
            if cont[68: 72] != b"0000" :          #if windows size is positive isnot zero
                #print("Port " + str(port) + " is: open")
                outputs[port] = 'open'
            else:
                #print("Port " + str(port) + " is: closed")
                outputs[port] = 'closed'
        else:                                                       # icmp eror (type3,code 1,2,3,9,10 or 13)
            #print("Port " + str(port) + " is: filtered")
            outputs[port] = 'filtered'


def dedicat_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    return s.getsockname()[1]

def dedicat_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    local_ip = s.getsockname()[0]
    return local_ip

def scan_connect_ports(host_ip, delay, first_porst, endport):
    threads = []  # To run TCP_connect concurrently
    output = {}  # For printing purposes

    # Spawning threads to scan ports
    for i in range(first_porst, endport):
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        threads.append(t)

    # Starting threads
    for i in range(endport-first_porst):
        threads[i].start()

    # Locking the main thread until all threads complete
    for i in range(endport-first_porst):
        threads[i].join()

    print("  -   -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -")
    print("open ports : ")
    # Printing listening ports from small to large
    for i in range(first_porst, endport):
        if output[i] == 'open':
            print(str(i) ,end=' , ' )

#-------------------------------------------------------------------------------------
def scan_tcp(my_ip, host_ip, my_port, host_port,delay, method,outputs):
    p = TCPpacket(my_ip, host_ip, my_port, host_port, method)
    try:
        result = p.send_packet(host_ip, delay)
        check_if_open(host_port, result,method,outputs)
        if(method == 0):    #we must send a rst to finish three way handshake
            p = TCPpacket(my_ip, host_ip, my_port, host_port, 4)  # send a rst packet to finish the connection
            try:
                result = p.send_packet(host_ip, delay)
            except:
                print("port " + str(host_port) + " : cannot send rst for finish the port")
    except:
        if(method==2): #fin scan      no response
            outputs[host_port] = 'open'
            #print("port " + str(host_port) + " : is open")
        #elif(method==3): #windows scan  nothing to say
         #   pass
        else:
            outputs[host_port] = 'filtered'
            #print("port " + str(host_port) + " : is filtered")




def scan_tcp_ports(host_name, delay, first_porst, end_port,method):
    threads = []  # To run TCP_connect concurrently
    outputs = {}
    my_ip = dedicat_local_ip()
    try:
        my_port = dedicat_local_port()
        host_ip = socket.gethostbyname(host_name)
    except:
        print("Unable to get Hostname and IP")

    # Spawning threads to scan ports
    for host_port in range(first_porst, end_port):
        t = threading.Thread(target=scan_tcp, args=(my_ip, host_ip, my_port, host_port, delay, method,outputs))
        threads.append(t)

    # Starting threads
    for i in range(end_port-first_porst):
        threads[i].start()

    # Locking the main thread until all threads complete
    for i in range(end_port-first_porst):
        threads[i].join()

    # Printing listening ports from small to large
    print("   -----------------------------------************-----------------------------------")
    print("open ports : ")
    for i in range(first_porst, end_port):
        if outputs[i] == 'open':
            print(str(i), end=' , ')
    print("  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  ")
    print("close ports : ")
    for i in range(first_porst, end_port):
        if outputs[i] == 'closed':
            print(str(i) ,end= ' , ')
    print("  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  ")
    print("filtered ports : ")
    for i in range(first_porst, end_port):
        if outputs[i] == 'filtered':
            print(str(i) ,end= ' , ')
    print("  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  ")
    print("unfiltered ports : ")
    for i in range(first_porst, end_port):
        if outputs[i] == 'unfiltered':
            print(str(i) , end=' , ')
    print("  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  ")


def main(argv):
    host_name=""
    delay = first_porst = end_port = method = 0
    try:
      opts, args = getopt.getopt(argv,"ht:f:l:s:d:",[])
    except getopt.GetoptError:
      print ('−t <host_name>  −f <firstport>  -l< lastport>   −s <type of scan>   −d <delay>')
      print ('type of scans: CS=connect scan  ,  TSS=tcp syn scan , TAS=tcp ack scan , TFS=tcp fin scan , TWS=tcp window scan')
      sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
         print ('−t <host_name>  −f <firstport>  -l<lastport> −s <type of scan> −𝑑 <delay>')
         print ('type of scans: CS=connect scan  ,  TSS=tcp syn scan , TAS=tcp ack scan , TFS=tcp fin scan , TWS=tcp window scan')
         sys.exit()
        elif opt in ('-t'):
            host_name=arg
        elif opt in ('-f'):
            first_porst=int(arg)
        elif opt in ('-l'):
            end_port=int(arg)
        elif opt in ('-d'):
            delay=int(arg)
        elif opt in ("-s"):           #remember method==4 is for making a rst tcp packet
            if(arg=='CS'):
                method=5
            elif(arg=='TSS'):
                method=0
            elif(arg=='TAS'):
                method=1
            elif(arg=='TFS'):
                method=2
            elif(arg=='TWS'):
                method=3
    if(method == 5):#connect scan
        host_ip=socket.gethostbyname(host_name)
        scan_connect_ports(host_ip, delay, first_porst, end_port)
    else:#tcp syn or ack or fin or window scannig
        scan_tcp_ports(host_name, delay, first_porst, end_port, method)



if __name__ == "__main__":
   main(sys.argv[1:])
