# kara_client.py
"""
KARA Protocol Client
Keyed Anonymous Randomized Architecture - Client implementation
"""
import socket
import hashlib
import random
import time
import os
import base64
import re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class KARAClient:
    """
    KARA Protocol Client implementation.
    Handles secure connection, key exchange, and per-character encryption.
    """
    
    def __init__(self, host='127.0.0.1', port=65432):
        """
        Initialize KARA client.
        
        Args:
            host: Server host address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = self.generate_key_pair()
        self.shared_key = None
        self.session_key = self.generate_session_key()

    def generate_key_pair(self):
        """
        Generate ECDH key pair for secure key exchange.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_session_key(self):
        """
        Generate unique SHA-256 session key for manual verification.
        
        Returns:
            Hex-encoded session key string
        """
        random_bytes = os.urandom(32)
        return hashlib.sha256(random_bytes).hexdigest()

    def derive_shared_key(self, peer_public_key):
        """
        Derive shared secret key using ECDH and HKDF.
        
        Args:
            peer_public_key: Peer's public key for key exchange
        """
        self.shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kara_key',
            backend=default_backend()
        ).derive(self.shared_key)

    def generate_char_key(self, char_index: int) -> bytes:
        """
        Generate unique encryption key for a specific character.
        
        Args:
            char_index: Index of the character in the message
            
        Returns:
            Encryption key bytes
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.shared_key,
            info=f"char_{char_index}".encode(),
            backend=default_backend()
        ).derive(self.shared_key)

    def decrypt_char(self, encrypted_char: str, char_index: int) -> str:
        """
        Decrypt a single character encrypted with AES-256-GCM.
        
        Args:
            encrypted_char: Base64-encoded encrypted character
            char_index: Index of character in message
            
        Returns:
            Decrypted character string
        """
        key = self.generate_char_key(char_index)
        data = base64.b64decode(encrypted_char.encode())
        iv, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def encrypt_char(self, char: str, char_index: int) -> str:
        """
        Encrypt a single character with AES-256-GCM.
        
        Args:
            char: Character to encrypt
            char_index: Index of character in message
            
        Returns:
            Base64-encoded encrypted character
        """
        key = self.generate_char_key(char_index)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(char.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def connect(self, recipient_session_key: str):
        """
        Establish connection with server and perform key exchange.
        
        Args:
            recipient_session_key: Session key of the recipient client
        """
        self.client_socket.connect((self.host, self.port))
        # Send own session key
        self.client_socket.sendall(self.session_key.encode() + b'\n')
        # Send recipient session key
        self.client_socket.sendall(recipient_session_key.encode() + b'\n')
        # Send public key
        self.client_socket.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        # Receive server's public key (DER format)
        peer_public_key_bytes = b''
        peer_public_key = None
        
        while peer_public_key is None:
            chunk = self.client_socket.recv(1024)
            if not chunk:
                break
            peer_public_key_bytes += chunk
            # Try to parse, if successful we have the full key
            try:
                peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
                break
            except ValueError:
                # Not enough data yet, continue receiving
                if len(peer_public_key_bytes) >= 500:  # Safety limit
                    raise ValueError("Failed to parse public key: invalid format")
                continue
        
        if peer_public_key is None:
            raise ValueError("Failed to receive public key")
        self.derive_shared_key(peer_public_key)
        # Set socket timeout for receive mode to prevent blocking forever
        self.client_socket.settimeout(5.0)  # 5 second timeout for recv operations

    def receive_message(self) -> str:
        """
        Receive and decrypt message from server character by character.
        Always sends ACK immediately to prevent server timeouts.
        
        Returns:
            Decrypted message string, or None if connection closed
        """
        message = ""
        char_index = 0
        buffer = b''
        
        while True:
            try:
                data = self.client_socket.recv(1024)
            except socket.timeout:
                # Timeout - continue waiting, don't return empty message
                continue
            except (ConnectionError, OSError):
                # Connection closed - return message if we have one
                return message if message else None
            
            if not data:
                # No data - return message if we have one
                return message if message else None
            
            buffer += data
            
            # Check for end-of-message marker
            if b"MSG_END" in buffer:
                msg_end_pos = buffer.find(b"MSG_END")
                # Process data before MSG_END
                if msg_end_pos > 0:
                    process_data = buffer[:msg_end_pos]
                    buffer = buffer[msg_end_pos + 7:]  # Remove processed data and MSG_END
                else:
                    # MSG_END at start, just remove it
                    buffer = buffer[7:]
                    # If we have a message, return it
                    if message:
                        return message
                    continue
                
                # Process characters before MSG_END
                process_buffer = process_data
                while len(process_buffer) >= 44:
                    try:
                        test_str = process_buffer.decode('utf-8', errors='ignore')
                        base64_match = re.match(r'([A-Za-z0-9+/]{40,}={0,2})', test_str)
                        if base64_match:
                            encrypted_char = base64_match.group(1)
                            encrypted_bytes = encrypted_char.encode()
                            try:
                                decrypted_char = self.decrypt_char(encrypted_char, char_index)
                                message += decrypted_char
                                char_index += 1
                                # Send ACK for this character
                                try:
                                    self.client_socket.sendall(b"ACK")
                                except Exception:
                                    pass
                            except Exception:
                                # Decryption failed - might be random message, still send ACK
                                try:
                                    self.client_socket.sendall(b"ACK")
                                except Exception:
                                    pass
                            process_buffer = process_buffer[len(encrypted_bytes):]
                        else:
                            break
                    except Exception:
                        if len(process_buffer) > 0:
                            process_buffer = process_buffer[1:]
                        else:
                            break
                
                # Return message when MSG_END is received
                if message:
                    return message
                continue
            
            # Process buffer to extract encrypted characters
            max_iterations = 100
            iteration = 0
            while len(buffer) >= 44 and iteration < max_iterations:
                iteration += 1
                try:
                    test_str = buffer.decode('utf-8', errors='ignore')
                    base64_match = re.match(r'([A-Za-z0-9+/]{40,}={0,2})', test_str)
                    
                    if base64_match:
                        encrypted_char = base64_match.group(1)
                        encrypted_bytes = encrypted_char.encode()
                        
                        # Try to decrypt with current char_index
                        decrypted = False
                        try:
                            decrypted_char = self.decrypt_char(encrypted_char, char_index)
                            message += decrypted_char
                            char_index += 1
                            decrypted = True
                        except Exception:
                            # Decryption failed - might be random message
                            pass
                        
                        # Always send ACK immediately (for both real and random messages)
                        try:
                            self.client_socket.sendall(b"ACK")
                        except Exception:
                            return message if message else None
                        
                        # Remove processed data
                        buffer = buffer[len(encrypted_bytes):]
                    else:
                        # No valid base64, might need more data
                        break
                except Exception:
                    # Error processing, skip one byte
                    if len(buffer) > 0:
                        buffer = buffer[1:]
                    else:
                        break
            
            # Prevent buffer overflow
            if len(buffer) > 2000:
                buffer = buffer[-500:]

    def send_message(self, message: str):
        """
        Send message character by character with per-character encryption.
        
        Args:
            message: Message to send
        """
        for char_index, char in enumerate(message):
            encrypted_char = self.encrypt_char(char, char_index)
            self.client_socket.sendall(encrypted_char.encode())
            
            # Wait for ACK, ignoring random messages from server
            ack_received = False
            buffer = b''
            timeout_count = 0
            max_timeout = 50  # Maximum attempts to find ACK
            
            while not ack_received and timeout_count < max_timeout:
                data = self.client_socket.recv(1024)
                if not data:
                    raise ConnectionError("Connection closed by server")
                
                buffer += data
                
                # Look for ACK in buffer
                if b"ACK" in buffer:
                    # Extract ACK and remove it from buffer
                    ack_pos = buffer.find(b"ACK")
                    buffer = buffer[ack_pos + 3:]  # Keep any remaining data
                    ack_received = True
                else:
                    # Random message, continue receiving
                    timeout_count += 1
                    # If buffer gets too large, something is wrong
                    if len(buffer) > 10000:
                        raise ConnectionError("Buffer overflow - too much random data")
            
            if not ack_received:
                raise ConnectionError("Failed to receive ACK from server")
            
            # Random delay between characters for traffic obfuscation
            time.sleep(random.uniform(0.1, 0.3))
        self.client_socket.close()


def main():
    """Main entry point for KARA client."""
    host = os.getenv('KARA_HOST', '127.0.0.1')
    port = int(os.getenv('KARA_PORT', '65432'))
    client = KARAClient(host=host, port=port)
    print(f"[*] Your session key: {client.session_key}")
    print("[*] Share this key with the person you want to communicate with.")
    
    mode = input("[*] Choose mode: (s)end message or (r)eceive messages? [s/r]: ").strip().lower()
    
    if mode == 'r' or mode == 'receive':
        # Receive mode: connect and wait for messages
        print("[*] Connecting to server in receive mode...")
        try:
            # Connect with empty recipient to indicate receive mode
            client.connect("")
            print("[*] Connected! Waiting for messages...")
            print("[*] (Press Ctrl+C to exit)")
            try:
                while True:
                    message = client.receive_message()
                    if message:
                        print(f"\n[+] Received message: {message}\n")
                        print("[*] Waiting for more messages...")
                    elif message is None:
                        # Connection closed
                        print("[!] Connection closed by server")
                        break
                    # If message is empty string, continue waiting (might be random messages)
            except KeyboardInterrupt:
                print("\n[!] Exiting...")
            except (ConnectionError, socket.error) as e:
                print(f"\n[!] Connection error: {e}")
            except Exception as e:
                print(f"\n[!] Error: {e}")
                import traceback
                traceback.print_exc()
        except (ConnectionError, socket.error) as e:
            print(f"[!] Connection error during setup: {e}")
        except Exception as e:
            print(f"[!] Error during setup: {e}")
    else:
        # Send mode: send a message
        recipient_key = input("[*] Enter recipient's session key: ")
        
        if not recipient_key or recipient_key.strip() == "":
            print("[!] Recipient key cannot be empty. Connection aborted.")
            return
        
        if recipient_key == client.session_key:
            print("[!] You cannot send messages to yourself. Connection aborted.")
            return
        
        try:
            client.connect(recipient_key.strip())
            message = input("[*] Enter your message: ")
            client.send_message(message)
            print("[!] Message sent and connection closed.")
        except (ConnectionError, socket.error) as e:
            print(f"[!] Connection error: {e}")
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
