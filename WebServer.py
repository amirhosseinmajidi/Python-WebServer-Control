import socket
import threading
connected_ips = []
blocked_ips = set()

SERVER_IP_ADR = "192.168.1.3"
firewall_ips = {"192.168.1.10", "192.168.1.10"}

connected_ips_lock = threading.Lock()

http_status_codes = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    501: "Not Implemented",
    503: "Service Unavailable"
}


def handle_client(client_socket, client_address):
    """
    Handles the connection with a client.

    Receives the client's request, processes it to determine the appropriate HTTP status code and message,
    constructs a response, and sends it back to the client. If the client's IP is blocked, the connection is closed immediately.

    :param client_socket: The socket representing the client's connection.
    :param client_address: The address of the client, which includes the IP address and port number.
    :return:
    """

    global connected_ips

    ip = client_address[0]

    with connected_ips_lock:
        if ip in blocked_ips:
            print(f"Blocked IP {ip} tried to connect.")
            client_socket.close()
            return
        list_size = len(set(connected_ips))
        connected_ips.append(ip)

    try:
        request = client_socket.recv(1024).decode()
        try:
            headers = request.split('\n')
            first_header_item = headers[0].split()
            method = first_header_item[0]
            path = first_header_item[1]
        except IndexError or UnboundLocalError:
            pass

        try:
            if path == '/':
                status_code = 200
            elif path == '/created':
                status_code = 201
            elif path == '/accepted':
                status_code = 202
            elif path == '/no-content':
                status_code = 204
            elif path == '/moved':
                status_code = 301
            elif path == '/found':
                status_code = 302
            elif path == '/not-modified':
                status_code = 304
            elif path == '/bad-request':
                status_code = 400
            elif path == '/unauthorized':
                status_code = 401
            elif path == '/forbidden':
                status_code = 403
            elif path == '/not-found':
                status_code = 404
            elif path == '/server-error':
                status_code = 500
            elif path == '/not-implemented':
                status_code = 501
            elif path == '/service-unavailable':
                status_code = 503
            else:
                status_code = 404
        except UnboundLocalError:
            return

        status_message = http_status_codes[status_code]
        bad_status_codes = [404, 503, 501, 500, 403, 401, 400, 304, 204]
        if status_code in bad_status_codes:
            with open('Browser2.html', 'r') as file:
                template = file.read()

            response_body = template.format(
                status_code=status_code,
                status_message=status_message,
                list_size=list_size
            )
            response = (
                f"HTTP/1.1 {status_code} {status_message}\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "\r\n"
                f"{response_body}"
            )
        else:
            with open('Browser.html', 'r') as file:
                template = file.read()

            response_body = template.format(
                status_code=status_code,
                status_message=status_message,
                list_size=list_size
            )
            response = (
                f"HTTP/1.1 {status_code} {status_message}\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "\r\n"
                f"{response_body}"
            )

        client_socket.sendall(response.encode())

    finally:
        with connected_ips_lock:
            if ip in connected_ips:
                connected_ips.remove(ip)
        client_socket.close()


def start_server(server_ip, server_port):
    """
    Starts the server to listen for incoming connections.

    Binds the server to the specified IP address and port, listens for incoming connections,
    and creates a new thread to handle each client connection.

    :param server_ip: The IP address of the server.
    :param server_port: The port number to bind the server to.
    """

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        ip = client_address[0]
        if ip not in connected_ips:
            connected_ips.append(client_address[0])

        with connected_ips_lock:
            if ip in firewall_ips:
                connected_ips.remove(ip)
                print(f"\033[91mFirewall blocked IP {ip} from connecting.\033[00m")
                client_socket.close()
                continue
        print("\033[93m\n------------------------------------------------------------------------------\033[00m")
        print(f"\033[93mA client with IP Address {client_address[0]} and Socket Number {client_address[1]} has connected.\033[00m")
        print("\033[93m------------------------------------------------------------------------------\033[00m")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()


def show_connected_ips():
    """
    Displays the list of currently connected IP addresses.
    """

    global connected_ips
    with connected_ips_lock:
        print("\033[96mConnected IPs:\033[00m")
        if len(connected_ips) == 0:
            print("\033[91mThere is no Connected IP!\033[00m")
        cc = 0
        for ip in set(connected_ips):
            if ip not in blocked_ips:
                if cc == len(set(connected_ips))-1:
                    print("\033[92m" + ip + "\033[00m")
                else:
                    print("\033[92m" + ip + "\033[00m", end=" - ")
                cc += 1


def disconnect_and_block_ip(ip):
    """
    Disconnects and blocks a specific IP address.

    :param ip: The IP address to disconnect and block.
    """

    global connected_ips, blocked_ips
    with connected_ips_lock:
        if ip in connected_ips:
            connected_ips.remove(ip)
            blocked_ips.add(ip)
            print("\033[96mDisconnected and blocked IP: \033[00m" + "\033[92m" + ip + "\033[00m")
        else:
            print(f"\033[91mIP {ip} not found in connected IPs.\033[00m")


def unblock_ip(ip):
    """
    Unblocks a specific IP address.

    :param ip: The IP address to unblock.
    """

    global connected_ips, blocked_ips
    with connected_ips_lock:
        if ip in blocked_ips or ip in firewall_ips:
            try:
                firewall_ips.remove(ip)
            except:
                blocked_ips.discard(ip)
            print("\033[96mIP \033[00m" + "\033[92m" + ip + "\033[00m" + "\033[96m has been unblocked from Blocked-List and Firewall.\033[00m")
        else:
            print(f"\033[91mIP {ip} is not in Blocked-List or Firewall!\033[00m")


def show_blocked_ips():
    """
    Displays the list of currently blocked IP addresses and firewall IP addresses.
    """

    global firewall_ips, blocked_ips
    print("\033[96mFirewall-IPs:\033[00m")
    if len(firewall_ips) == 0:
        print("\033[91mThere is no IP in Firewall!\033[00m")
    else:
        cf = 0
        for ip in firewall_ips:
            if cf == len(firewall_ips)-1:
                print("\033[92m" + ip + "\033[00m")
            else:
                print("\033[92m" + ip + "\033[00m", end=' - ')
            cf += 1

    print("\033[96mBlocked-IPs:\033[00m")
    if len(blocked_ips) == 0:
        print("\033[91mThere is no IP in Blocked List!\033[00m")
    else:
        cb = 0
        for ip in blocked_ips:
            if cb == len(blocked_ips)-1:
                print("\033[92m" + ip + "\033[00m")
            else:
                print("\033[92m" + ip + "\033[00m", end=' - ')
            cb += 1


server_thread = threading.Thread(target=start_server, args=(SERVER_IP_ADR, 8080))
server_thread.start()


def server_management():
    while True:
        print("\n\033[96mServer Management Menu:")
        print("1. Show connected IPs")
        print("2. Disconnect and block an IP")
        print("3. Unblock IP")
        print("4. Show blocked IPs")
        print("5. Exit\033[00m")
        try:
            choice = input("\033[95mEnter your choice: \033[00m")
        except KeyboardInterrupt:
            exit("\n\nThe Web Server has closed.\nGood Luck.")

        if choice == '1':
            show_connected_ips()
        elif choice == '2':
            ip = input("\033[95mEnter the IP to disconnect and block: \033[00m")
            disconnect_and_block_ip(ip)
        elif choice == '3':
            ip = input("\033[95mEnter the IP to unblocking: \033[00m")
            unblock_ip(ip)
        elif choice == '4':
            show_blocked_ips()
        elif choice == '5':
            print("\033[93mmanagement panel closed\033[00m")
            break
        else:
            print("\033[91mInvalid choice. Please try again.\033[00m")

        print("\033[96m------------------------------------------------------------------------------\033[00m", end='')


server_management()
