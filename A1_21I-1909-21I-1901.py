import scapy.all as scapy
import socket

#########################XMAS Scan##################################

def xmas_scan(target_ip, target_ports):
    # Create a list of ports to scan
    ports_to_scan = [int(port) for port in target_ports.split(",")]

    # Send the Christmas Tree packets
    for port in ports_to_scan:
        # Create a TCP packet with the FIN, URG, and PUSH flags set to 1
        packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="FPU") # create chritmas tree packet and send to target

        # Send the packet and capture the response
        response = scapy.sr1(packet, timeout=1, verbose=0)

        # Check the response
        if response:
            if response.haslayer(scapy.TCP):# responce recived
                if response.getlayer(scapy.TCP).flags == 20:
                    print(f"Port {port} is open (XMAS scan)")
                else:
                    print(f"Port {port} is closed (XMAS scan)")
            else:
                print(f"Port {port} is closed (XMAS scan)")
        else:
            print(f"Port {port} is filtered (XMAS scan)") #the responce was not recived due to firewall or etc

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP address
    target_ports = "80,443,22"  # Replace with your target ports

    xmas_scan(target_ip, target_ports)
 
print("--------------------------------------") 





###########################SYN Scan####################



def syn_scan(target_ip, target_ports):
    # Create a list of ports to scan
    ports_to_scan = [int(port) for port in target_ports.split(",")]

    for port in ports_to_scan:
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #AF_INET=IPv4,SocK_Stream=TCP

            # Set a timeout for the connection attempt
            sock.settimeout(1)

            # Attempt to connect to the target port with a SYN packet
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                print(f"Port {port} is open (SYN/Stealth scan)")
            else:
                print(f"Port {port} is closed (SYN/Stealth scan)")       #send reset flag

            # Close the socket
            sock.close()
        except KeyboardInterrupt:       
            print("Scan stopped by user.")
            break
        except socket.error:
            print("Couldn't connect to the target.")
            break

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP address
    target_ports = "80,443,22"  # Replace with your target ports

    syn_scan(target_ip, target_ports)

print("--------------------------------------") 




#################### FIN Scan############################
def fin_scan(target_ip, target_ports): # send to close a connection
    # Create a list of ports to scan
    ports_to_scan = [int(port) for port in target_ports.split(",")]

    for port in ports_to_scan:
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt
            sock.settimeout(1)

            # Attempt to connect to the target port with a FIN packet
            sock.connect((target_ip, port))
            sock.send(b'\x01')  # Send a FIN packet

            # Receive data from the socket (if any)
            response = sock.recv(1024)

            if not response:
                print(f"Port {port} is open (FIN scan)")
            else:
                print(f"Port {port} is closed (FIN scan)")

            # Close the socket
            sock.close()
        except KeyboardInterrupt:
            print("Scan stopped by user.")
            break
        except ConnectionRefusedError:
            print(f"Port {port} is closed (FIN scan)")
        except socket.timeout:
            print(f"Port {port} is open (FIN scan)")
        except Exception as e:
            print(f"An error occurred while scanning port {port}: {str(e)}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP address
    target_ports = "80,443,22"  # Replace with your target ports

    fin_scan(target_ip, target_ports)

print("--------------------------------------") 



##########################NULL Scan#############################

def null_scan(target_ip, target_ports):
    # Create a list of ports to scan
    ports_to_scan = [int(port) for port in target_ports.split(",")]

    for port in ports_to_scan:
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt
            sock.settimeout(1)

            # Attempt to connect to the target port with a NULL packet
            sock.connect((target_ip, port))
            sock.send(b'\x00')  # Send a NULL packet

            # Receive data from the socket (if any)
            response = sock.recv(1024)

            if not response:
                print(f"Port {port} is open (NULL scan)")
            else:
                print(f"Port {port} is closed (NULL scan)")

            # Close the socket
            sock.close()
        except KeyboardInterrupt:
            print("Scan stopped by user.")
            break
        except ConnectionRefusedError:
            print(f"Port {port} is closed (NULL scan)")
        except socket.timeout:
            print(f"Port {port} is open (NULL scan)")
        except Exception as e:
            print(f"An error occurred while scanning port {port}: {str(e)}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP address
    target_ports = "80,443,22"  # Replace with your target ports

    null_scan(target_ip, target_ports)

print("--------------------------------------") 

########################ACK Scan###########################

def ack_scan(target_ip, target_ports):
    # Create a list of ports to scan
    ports_to_scan = [int(port) for port in target_ports.split(",")]

    for port in ports_to_scan:
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout for the connection attempt
            sock.settimeout(1)

            # Attempt to connect to the target port with an ACK packet
            sock.connect((target_ip, port))
            sock.send(b'\x10')  # Send an ACK packet

            # Receive data from the socket (if any)
            response = sock.recv(1024)

            if not response:
                print(f"Port {port} is unfiltered (ACK scan)")
            else:
                print(f"Port {port} is filtered (ACK scan)")

            # Close the socket
            sock.close()
        except KeyboardInterrupt:
            print("Scan stopped by user.")
            break
        except ConnectionRefusedError:
            print(f"Port {port} is unfiltered (ACK scan)")
        except socket.timeout:
            print(f"Port {port} is filtered (ACK scan)")
        except Exception as e:
            print(f"An error occurred while scanning port {port}: {str(e)}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Replace with your target IP address
    target_ports = "80,443,22"  # Replace with your target ports

    ack_scan(target_ip, target_ports)

print("--------------------------------------") 




