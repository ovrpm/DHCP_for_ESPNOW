import time
import espnow
import network
import struct
from binascii import crc32
from cryptolib import aes

MAC_TO_NID = {}
NID = 0x00
#set lease_time = 60 seconds for testing
LEASE_TIME = 60

reg = network.WLAN(network.STA_IF)
reg.active(True)
e = espnow.ESPNow()
e.active(True)

AES_KEY = "2A462D4A614E645267556B5870327335"
NETWORK_KEY = "CSCI437:ILOVEIOT"

#add peer only if it isn't already present
def network_add_peer(mac_address):
    peers = e.get_peers()
    
    for peer in peers:
        if peer[0] == mac_address:
            return None
        
    e.add_peer(mac_address)

#adds node to the map
#returns NID of the node
def add_node(mac, node_time):
    global NID
    
    if mac in MAC_TO_NID:
        print("the node is already registered, NID and expiration time are: " + str(MAC_TO_NID[mac]))
        return (MAC_TO_NID[mac])[0]
    else:
        if (len(MAC_TO_NID) == (2 ** 32)):
            print("cannot register node, map is full!")
            return None
        
        if (MAC_TO_NID):
            while (NID in list(MAC_TO_NID.values())[0] or NID == (2 ** 32 + 1)):
                if (NID == (2 ** 32 + 1)):
                    NID = 0
                NID += 1
        
        MAC_TO_NID[mac] = [NID, node_time]
        print("registration successful, list of registered nodes: " + str(MAC_TO_NID))
        return NID

#constantly scan the broadcast channel
#if registration request is recieved, assign nid and keep scanning
#if request to renew a lease is recieved, renew it and keep scanning
def scan_broadcast(time_start):
    while True:
        print("scanning for packets...")
        try:
            if (time.time() - time_start) % (LEASE_TIME / 12) == 0:
                check_expired()
            
            mac, msg = e.recv(1000)
            
            if not msg:
                continue
            
            #if recieved request to join network:
            elif msg[0] == 0:
                register_node(mac, msg)
            
            elif msg[0] == 3:
                renew_lease(mac, msg)
                
            elif msg[0] == 6:
                release_node(mac, msg)
                        
        except Exception as err:
            print("Error:", err)

#release node from the system, send ack back to the node
def release_node(mac, msg):
    if mac in MAC_TO_NID:
        print(f"node with NID = {(MAC_TO_NID[mac])[0]} is released")
        MAC_TO_NID.pop(mac)
        print("MAC_TO_NID:")
        print(MAC_TO_NID)
    
    data = struct.pack("B", 7)
    e.send(mac, data)

#process the registration request packet
def register_node(mac, msg):
    network_add_peer(mac)

    # unpack the CRC that we received
    recv_crc = struct.unpack('!I', msg[(len(msg)-4):len(msg)])[0]
    calc_crc = crc32(msg[:len(msg)-4])
    if (calc_crc == recv_crc):
        print("CRC OK")
    else:
        print("CRC BAD")
        return None
    try:
        aes_data = aes(AES_KEY, 1)
        dec_data = msg[1:17]
        password_raw = aes_data.decrypt(dec_data)
        password_utf = password_raw.decode('utf-8')
        
        if password_utf == NETWORK_KEY:
            print("key correct, authentication successful")
        
            node_time = struct.unpack("!H", msg[17:19])
            
            node_time = (node_time[0] + LEASE_TIME) % 65535
            server_time = time.time() + LEASE_TIME
            
            NID = add_node(mac, server_time)
            
            data_offer = struct.pack("BIH", 1, NID, node_time)

            e.send(mac, data_offer)
        else:
            print("key incorrect, authentication failed")
            
            data_offer = struct.pack("B", 2)
            e.send(mac, data_offer)

    except Exception as ex:
        print(ex)

#process the lease renewal packet
def renew_lease(mac, msg):
    if mac not in MAC_TO_NID:
        #nack
        print("cannot renew lease, the node isnt registered")
        data_offer = struct.pack("B", 5)
        try:
            e.send(mac, data_offer)
        except Exception as err:
            print("Hiiiiii!" + err)
            
        return None
    
    node_time = struct.unpack("!H", msg[1:3])
    node_time = (node_time[0] + LEASE_TIME) % 65535
    
    server_time = time.time() + LEASE_TIME
    (MAC_TO_NID[mac])[1] = server_time % 65535
    print(f"lease of the node NID = {(MAC_TO_NID[mac])[0]} is renewed, sending ack...")
    
    #ack
    data_offer = struct.pack("BIH", 4, NID, node_time)
    e.send(mac, data_offer)

#check the MAC_TO_NID map for expired leases
def check_expired():
    print("Checking for expired leases...")
    if not MAC_TO_NID:
        print("there are no nodes registered in the system")
        return None
    
    for mac in MAC_TO_NID:
        _, exp_time = MAC_TO_NID[mac]
        if time.time() > exp_time:
            MAC_TO_NID.pop(mac)
            
    print("MAC_TO_NID:")
    print(MAC_TO_NID)
    
#int main():
time_start = time.time()
scan_broadcast(time_start)