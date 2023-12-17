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

def send_message(message):
    encrypted_message = double_ratchet_encrypt(message)
    print(f"Sending: {message}")  # Debugging print statement
    client.publish(f"{name}.out", encrypted_message)

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(f"{name}.in")
        # Send a predefined message on startup
        send_message("Hello, this is a predefined message!")
        print("Decrypted message: Hello,this is a predefined message!")
    else:
        print(f"Connection failed with error code {rc}")

def on_message(client, userdata, msg):
    global receiver_public_key
    if msg.topic == f"{name}.in":
        if receiver_public_key == b'':
            receiver_public_key = msg.payload
        else:
            decrypted_message = double_ratchet_decrypt(msg.payload)
            print(f"Received raw message: {msg.payload}")  # Debugging print statement
            print(f"Decrypted message: {decrypted_message}")  # Debugging print statement
            chat_text.insert(tk.END, f"Received: {decrypted_message}\n")
            chat_text.see(tk.END)
            root.update_idletasks()

client.on_connect = on_connect
client.on_message = on_message

def on_disconnect(client, userdata, rc):
    if rc != 0:
        print("Unexpected disconnection")

try:
    client.on_disconnect = on_disconnect
    client.connect("test.mosquitto.org", 1883, 60)  # Using a different MQTT broker
    print("Connection established")  # Debugging statement
    client.loop_start()  # Start the MQTT loop

    root = tk.Tk()
    root.title(f"Double Ratchet Chat ({name})")

    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)

    chat_text = tk.Text(frame, width=50, height=20)
    chat_text.pack(padx=10, pady=10)

    entry = tk.Entry(frame, width=40)
    entry.pack(padx=10, pady=10)

    def send_entry_message(event=None):
        message = entry.get()
        entry.delete(0, tk.END)
        send_message(message)

    entry.bind("<Return>", send_entry_message)

    send_button = tk.Button(frame, text="Send", command=send_entry_message)
    send_button.pack(padx=10, pady=10)

    root.mainloop()

except ConnectionRefusedError:
    print("Connection refused: Check broker address or network connectivity")
