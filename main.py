import tkinter as tk
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Randomly generated 128-bit root key
root_key = secrets.token_bytes(16)
name = "Klara"

# Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_key = parameters.generate_private_key()
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# client1 = mqtt.Client()
# client2 = mqtt.Client()

# Double Ratchet-related variables
sender_chain_key = root_key
receiver_chain_key = root_key
sender_public_key = public_key
receiver_public_key = b''  # Placeholder for the receiver's public key

# MQTT initialization
client = mqtt.Client()

# Derive key using HKDF
def derive_key(chain_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'',
        backend=default_backend()
    )
    derived_key = hkdf.derive(chain_key)
    return derived_key
# def send_message_from_client1_to_client2(message):
#     encrypted_message = double_ratchet_encrypt(message)
#     client2.on_message(client2, None, None, encrypted_message)
# def receive_message_on_client2(encrypted_message):
#     global client2_receiver_public_key
#     if client2_receiver_public_key == b'':  # If receiver's public key is not set
#         client2_receiver_public_key = client1_sender_public_key
#     else:
#         decrypted_message = double_ratchet_decrypt(encrypted_message)
#         print(f"Client 2 received: {decrypted_message}")

# client1.on_message = receive_message_on_client2

# Placeholder functions for encryption and decryption
def double_ratchet_encrypt(message):
    global sender_chain_key
    derived_key = derive_key(sender_chain_key)
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)  # Generate a unique nonce
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return ciphertext

def double_ratchet_decrypt(encrypted_message):
    global receiver_chain_key
    derived_key = derive_key(receiver_chain_key)
    aesgcm = AESGCM(derived_key)
    nonce = secrets.token_bytes(12)  # Replace with the received nonce
    plaintext = aesgcm.decrypt(nonce, encrypted_message, None)
    return plaintext.decode()

# MQTT connection and message handling
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(f"{name}.in")
    else:
        print(f"Connection failed with error code {rc}")

def on_message(client, userdata, msg):
    global receiver_public_key
    if msg.topic == f"{name}.in":
        if receiver_public_key == b'':  # If receiver's public key is not set
            receiver_public_key = msg.payload
        else:
            decrypted_message = double_ratchet_decrypt(msg.payload)
            print(f"Received: {decrypted_message}")

client.on_connect = on_connect
client.on_message = on_message
client.connect("mqtt.eclipse.org", 1883, 60)  # Replace with your MQTT broker details

# Tkinter GUI setup
def send_message(event=None):
    message = entry.get()
    entry.delete(0, tk.END)

    # Encrypt the message using Double Ratchet-like placeholders
    encrypted_message = double_ratchet_encrypt(message)

    # Send the encrypted message via MQTT
    client.publish(f"{name}.out", encrypted_message)

root = tk.Tk()
root.title(f"Double Ratchet Chat ({name})")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

chat_text = tk.Text(frame, width=50, height=20)
chat_text.pack(padx=10, pady=10)

entry = tk.Entry(frame, width=40)
entry.pack(padx=10, pady=10)
entry.bind("<Return>", send_message)

send_button = tk.Button(frame, text="Send", command=send_message)
send_button.pack(padx=10, pady=10)

root.mainloop()
