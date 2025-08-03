# Python-WebServer-Control

A simple yet powerful multi-threaded web server built with Python's standard libraries, featuring a real-time command-line interface for administrative control and IP management.

This project demonstrates the fundamentals of socket programming, multi-threading, and real-time server management, including features like a basic firewall, dynamic IP blocking, and connection monitoring.

## ✨ Key Features

- **Multi-threaded Architecture**: Handles multiple client connections concurrently without blocking the main process.
- **Interactive Admin Console**: A command-line interface (CLI) to manage the server in real-time.
- **Dynamic IP Blocking**: Block suspicious IP addresses on the fly.
- **Built-in Firewall**: Pre-define a list of IPs to be blocked automatically.
- **Connection Monitoring**: View a list of all currently connected client IPs.
- **HTTP Status Code Simulation**: Responds with appropriate HTTP status codes based on the requested URL path (e.g., `200 OK`, `404 Not Found`, `403 Forbidden`).
- **Standard Libraries Only**: No external dependencies required. Built purely with Python's `socket` and `threading` libraries.

## ⚙️ Usage

1.  **Run the server:**
    Execute the `WebServer.py` script. The server will start listening for connections in the background, and the management console will appear in your terminal.

    ```sh
    python WebServer.py
    ```

2.  **Use the Management Console:**
    Once the server is running, you will see the management menu. You can interact with the server by choosing one of the following options:

    ```
    Server Management Menu:
    1. Show connected IPs
    2. Disconnect and block an IP
    3. Unblock IP
    4. Show blocked IPs
    5. Exit
    Enter your choice:
    ```

    - **To view connected clients**: Type `1` and press Enter.
    - **To block a client**: Type `2`, press Enter, and provide the IP address you wish to block.
    - **To unblock an IP**: Type `3`, press Enter, and provide the IP address to remove from the blocklist.
  
  
