# MTProto Client Application

This project is a simple MTProto client built using Python, Flask-SocketIO, and Tkinter for a graphical user interface. It establishes a secure connection to a server using Diffie-Hellman key exchange and encrypts messages using the MTProto 2.0 protocol.

## Features

- **Secure Messaging**: Encrypts and decrypts messages using MTProto 2.0.
- **Socket.IO Integration**: Real-time communication with a server.
- **GUI**: User-friendly interface using Tkinter.
- **Threaded Networking**: Keeps the GUI responsive while handling network communication in a separate thread.

## Requirements

Ensure you have the following Python libraries installed:

- `cryptography==38.0.1`
- `Flask==2.2.2`
- `Flask_SocketIO==5.1.1`
- `pycryptodome==3.15.0`
- `python-socketio==5.11.2`
- `TgCrypto==1.2.5`

You can install the dependencies using:

```bash
pip install -r requirements.txt
```

## Key Components

### 1. Encryption and Decryption

- **Inner Layer Encryption**: Encrypts the message payload.
- **Outer Layer Encryption**: Adds authentication and session management.
- **Key Derivation**: Uses SHA256 and SHA1 hashing for deriving keys and initializing AES-IGE mode.

### 2. Diffie-Hellman Key Exchange

- Uses fixed parameters for DH key exchange.
- Exchanges keys securely with the server to establish a shared secret.

### 3. GUI

- Built using Tkinter.
- Displays sent and received messages.
- Allows user interaction for sending messages.

### 4. Socket.IO

- Manages real-time communication with the server.
- Handles events like `connect`, `disconnect`, `server_hello`, and `receive_message`.

## File Structure

- `mtproto_client.py`: Main application file.
- `dh_config.py`: Contains the `get_fixed_dh_parameters` function for DH key exchange.

## Notes

- Ensure the server supports the MTProto 2.0 protocol.
- The `dh_config.py` file should define the Diffie-Hellman parameters to be used for key exchange.

## License

This project is open-source and available under the MIT License.
