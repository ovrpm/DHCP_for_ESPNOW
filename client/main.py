import time
import espnow
import struct
#import sys
import network
from binascii import crc32
from cryptolib import aes

BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

#keys
AES_KEY = "2A462D4A614E645267556B5870327335"
NETWORK_KEY = "CSCI437:ILOVEIOT"

#uninitialized data
#smth = 0
MY_NID = 0xff 
HOST_MAC = b'\xff\xff\xff\xff\xff\xff'
expire_time = -1
TIME_SENT = -1

reg = network.WLAN(network.STA_IF)
reg.active(True)
e = espnow.ESPNow()
e.active(True)
e.add_peer(BROADCAST_MAC)

#add peer only if it isn't already present
def network_add_peer(mac_address):
    peers = e.get_peers()
    
    for peer in peers:
        if peer[0] == mac_address:
            return None
        
    e.add_peer(mac_address)
        
#check if the lease expired, or if we need to send lease renew request
def check(lease_time):
    #global smth
    
    try:
        now = time.time() % 65536
        
        print(f"Current time: {now}")
        print(f"Estimated lease time: {lease_time}")
        print(f"Baseline time: {TIME_SENT}")
        print("operating...")
        
        if now < TIME_SENT:
            time_passed = now - TIME_SENT + 65536
        else:
            time_passed = now - TIME_SENT 
        
        if time_passed >= lease_time:
            print("lease expired")
            
            return None
        elif time_passed >= (lease_time) / 2:
            print("halftime expired, requesting new lease...")
            '''
            if smth == 0:
                time.sleep(40)
                smth += 1
            '''
            enter_network(3)
            return None
    
    except Exception as ex:
        print("In check: ", ex)        

def enter_network(code):
    global MY_NID, TIME_SENT, HOST_MAC, expire_time
    
    #registration
    if code == 0:
        
        aes_data_cypher = aes(AES_KEY, 1)
        enc = aes_data_cypher.encrypt(NETWORK_KEY) # encrypt message
        
        for _ in  range(5):           
            TIME_SENT = time.time()
            time_last16bits = time.time() % 65536
            
            DATA_BEFORE = struct.pack("!B16sH", code, enc, time_last16bits) # struct data for CRC calc
            calc_crc = crc32(DATA_BEFORE) # calc CRC based on whole data
            DATA = struct.pack('!B16sHI', code, enc, time_last16bits, calc_crc) # add CRC to and pack data
            
            print("Sending registration message to broadcast...")
            e.send(BROADCAST_MAC, DATA)
            
            try:
                HOST_MAC, msg = e.recv(5000)
                
                if not msg:
                    continue
                
                if (msg[0] == 1):
                    network_add_peer(HOST_MAC)
                    type_msg, MY_NID, expire_time = struct.unpack('BIH', msg)
                    
                    current_time_after_receiving = time.time()
                    print("Connection successful! NID assigned:", str(MY_NID))
                    
                    return HOST_MAC, MY_NID, expire_time
                elif (msg[0] == 2):
                    print("key is incorrect, check preshared value")
                    return None
            
            except Exception as ex:
                print("In enter_network: ", ex)
                
        print("no server found, terminating...")
        return None
    
    #renew lease
    elif code == 3:        
        #trying to renew, until ack is recieved
        while True:
            TIME_SENT = time.time()
            time_last16bits = TIME_SENT % 65536
        
            DATA = struct.pack('!BI', code, time_last16bits)
            
            e.send(HOST_MAC, DATA)
            
            try:
                HOST_MAC, msg = e.recv(5000)
                
                if not msg:
                    return None
                
                if msg[0] == 4:
                    expire_time = struct.unpack("!H", msg[1:3])
                    print("new lease aquired!")
                    return None
                
                if msg[0] == 5:
                    print("Tried to renew lease, but the node isn't  registered")
                    _, MY_NID, expire_time = enter_network(0)
                    return None
                
            except Exception as ex:
                    print("In renew lease: ", ex)
    
    #exit network, release the lease
    elif code == 6:
        DATA = struct.pack('!B', code)
        e.send(HOST_MAC, DATA)
        
        try:
            HOST_MAC, msg = e.recv(5000)
            
            if not msg:
                return None
            
            if msg[0] == 7:
                print("lease released, exit completed")
                return None
            
        except Exception as ex:
                print("In renew lease: ", ex)
        
#int main():
# Try to enter network
try:
    _, MY_NID, expire_time = enter_network(0)
except Exception as err:
    print("registration failed", err)

#if registration is done (and expire_time innitialized)
#periodically check if halftime of the lease has passsed
if (expire_time != -1):
    lease_time = expire_time - TIME_SENT
    for i in range(15):
        #emulate work done by the node
        time.sleep(lease_time / 12)
        check(lease_time)
    enter_network(6)