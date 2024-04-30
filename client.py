import socketio
import tgcrypto
import uuid

from dh_config import get_fixed_dh_parameters
from hashlib import sha256, sha1
from cryptography.hazmat.primitives import serialization
from Crypto.Util.Padding import unpad, pad

sio = socketio.Client()
server_url = 'http://127.0.0.1:5001'
client_id = str(uuid.uuid4())
session_id = ''
shared_secret = None
salt = None

parameters = get_fixed_dh_parameters()
private_key = parameters.generate_private_key()
 
def encrypt_inner_layer(shared_secret, message):
    # MTProto 2.0 part II Encryption
    message_bytes = message if isinstance(message, bytes) else message.encode('utf-8')
    padded_payload = pad(message_bytes, 16)
    msg_key = sha256(shared_secret + padded_payload).digest()[:16]
    aes_key, aes_ige_iv = derive_ige_key_and_iv(shared_secret, msg_key)
    if len(aes_ige_iv) < 32:
        aes_ige_iv = aes_ige_iv + aes_ige_iv
    encrypted_data = tgcrypto.ige256_encrypt(padded_payload, aes_key, aes_ige_iv)
    encrypted_message = msg_key + encrypted_data
    return encrypted_message

def encrypt_outer_message(shared_secret, message, server_salt, session_id):
    # MTProto 2.0 part I Encryption
    auth_key_id = sha1(shared_secret).digest()[:8]
    payload = server_salt + session_id + message
    padded_payload = pad(payload, 16)

    msg_key = sha256(shared_secret + padded_payload).digest()[:16]
    aes_key, aes_ige_iv = derive_ige_key_and_iv(shared_secret, msg_key)

    if len(aes_ige_iv) < 32:
        aes_ige_iv = aes_ige_iv + aes_ige_iv

    encrypted_data = tgcrypto.ige256_encrypt(padded_payload, aes_key, aes_ige_iv)
    encrypted_message = auth_key_id + msg_key + encrypted_data
    return encrypted_message

def send_encrypted_message(message):
    global shared_secret, salt, session_id
    if not all([shared_secret, salt, session_id]):
        print("parameters not initialized.")
        return
    
    if isinstance(session_id, str):
        session_id = session_id.encode('utf-8')

    inner_layer_encrypted_message = encrypt_inner_layer(shared_secret, message)
    encrypted_message = encrypt_outer_message(shared_secret, inner_layer_encrypted_message, salt, session_id)
    return encrypted_message

def derive_ige_key_and_iv(shared_secret, msg_key):
    if not isinstance(shared_secret, bytes):
        raise TypeError("shared_secret must be bytes")
    if not isinstance(msg_key, bytes):
        raise TypeError("msg_key must be bytes")
    
    aes_key = sha256(msg_key + shared_secret).digest() 
    aes_ige_iv = sha256(shared_secret + msg_key).digest()

    return aes_key[:32], aes_ige_iv[:32]

def decrypt_message(encrypted_payload):
    global shared_secret

    auth_key_id = encrypted_payload[:8]
    msg_key = encrypted_payload[8:24]
    encrypted_data = encrypted_payload[24:]

    # MTProto 2.0 part I Decryption
    aes_key, aes_ige_iv = derive_ige_key_and_iv(shared_secret, msg_key)
    decrypted_outer = tgcrypto.ige256_decrypt(encrypted_data, aes_key, aes_ige_iv)

    try:
        decrypted_outer_unpadded = unpad(decrypted_outer, 16)[28:]
    except ValueError:
        print("Padding error on decrypted outer layer.")
        return None
    
    auth_key_fragment = shared_secret[:32]
    outer_calculated_msg_key = sha256(auth_key_fragment + decrypted_outer).digest()[:16]

    if outer_calculated_msg_key != msg_key:
        raise ValueError("Outer Message key verification failed!")
    else:
        print("Outer Message key verification successful")

    # MTProto 2.0 part II Decryption
    inner_msg_key = decrypted_outer_unpadded[:16]
    encrypted_inner_message = decrypted_outer_unpadded[16:]

    aes_key, aes_ige_iv = derive_ige_key_and_iv(shared_secret, inner_msg_key)
    decrypted_inner = tgcrypto.ige256_decrypt(encrypted_inner_message, aes_key, aes_ige_iv)
    
    try:
        decrypted_inner_unpadded = unpad(decrypted_inner, 16)
    except ValueError:
        print("Padding error on decrypted inner layer.")
        return None
    
    auth_key_fragment = shared_secret[:32]
    calculated_msg_key = sha256(auth_key_fragment + decrypted_inner).digest()[:16]

    if calculated_msg_key != inner_msg_key:
        raise ValueError("Message key verification failed!")
    else:
        print("Message key verification successful")

    return decrypted_inner_unpadded.decode('utf-8')

@sio.event
def connect():
    print('Connected to server.')
    sio.emit('client_hello', {'client_id': client_id})

@sio.on('server_hello')
def on_server_hello(data):
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    sio.emit('client_exchange', {'client_id': client_id, 'peer_public_key': pem_public_key})

@sio.on('exchange_complete')
def on_exchange_complete(data):
    global shared_secret, salt,session_id
    session_id = data['session_id']
    shared_secret = bytes.fromhex(data['key'])
    salt = bytes.fromhex(data['salt'])
    print('Exchange complete, ready to send and receive encrypted messages.')

@sio.on('receive_message')
def on_receive_message(data):
    encrypted_message = data['message']
    decrypt = decrypt_message(encrypted_message)
    print(decrypt,"decrypt_message")
    return

@sio.event
def disconnect():
    print('Disconnected from server.')

if __name__ == '__main__':
    try:
        sio.connect(server_url)
        while True:
            message = input('Enter a message ("exit" to quit): ')
            if message.lower() == 'exit':
                break
            encrypted_message = send_encrypted_message(message)
            sio.emit('send_message', {'client_id': client_id, 'message': encrypted_message})
    finally:
        sio.disconnect()