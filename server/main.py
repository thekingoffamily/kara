# kara_server.py
"""
KARA Protocol Server
Keyed Anonymous Randomized Architecture - Server implementation
"""
import socket
import threading
import hashlib
import random
import time
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend


class KARAServer:
    """
    KARA Protocol Server implementation.
    Handles client connections, key exchange, message decryption, and traffic obfuscation.
    """
    
    def __init__(self, host='127.0.0.1', port=65432):
        """
        Initialize KARA server.
        
        Args:
            host: Server host address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = self.generate_key_pair()
        # Dictionary: {session_key: (conn, addr, shared_key, char_index, last_activity, recipient_key, is_waiting)}
        # is_waiting: True if client is waiting to receive messages, False if sending
        self.clients = {}
        self.lock = threading.Lock()  # Lock for thread-safe access to clients dict

    def generate_key_pair(self):
        """
        Generate ECDH key pair for secure key exchange.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_shared_key(self, peer_public_key):
        """
        Derive shared secret key using ECDH and HKDF.
        
        Args:
            peer_public_key: Peer's public key for key exchange
            
        Returns:
            Shared key bytes
        """
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kara_key',
            backend=default_backend()
        ).derive(shared_key)

    def generate_char_key(self, shared_key: bytes, char_index: int) -> bytes:
        """
        Generate unique encryption key for a specific character.
        
        Args:
            shared_key: Shared secret key
            char_index: Index of the character in the message
            
        Returns:
            Encryption key bytes
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=shared_key,
            info=f"char_{char_index}".encode(),
            backend=default_backend()
        ).derive(shared_key)

    def encrypt_char_for_recipient(self, shared_key: bytes, char: str, char_index: int) -> str:
        """
        Encrypt a character for sending to recipient.
        
        Args:
            shared_key: Shared secret key with recipient
            char: Character to encrypt
            char_index: Index of character in message
            
        Returns:
            Base64-encoded encrypted character
        """
        key = self.generate_char_key(shared_key, char_index)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(char.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_char(self, shared_key: bytes, encrypted_char: str, char_index: int) -> str:
        """
        Decrypt a single character encrypted with AES-256-GCM.
        
        Args:
            shared_key: Shared secret key
            encrypted_char: Base64-encoded encrypted character
            char_index: Index of character in message
            
        Returns:
            Decrypted character string
        """
        key = self.generate_char_key(shared_key, char_index)
        data = base64.b64decode(encrypted_char.encode())
        iv, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def send_random_message(self, conn, shared_key):
        """
        Send random encrypted message for traffic obfuscation.
        
        Args:
            conn: Client connection socket
            shared_key: Shared secret key
        """
        random_char = chr(random.randint(32, 126))
        # Use negative index for random messages
        random_key = self.generate_char_key(shared_key, -1)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(random_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(random_char.encode()) + encryptor.finalize()
        encrypted_random = base64.b64encode(iv + encryptor.tag + ciphertext).decode()
        conn.sendall(encrypted_random.encode())

    def route_message_to_recipient(self, sender_key: str, recipient_key: str, message: str):
        """
        Route decrypted message to the recipient client.
        
        Args:
            sender_key: Session key of the sender
            recipient_key: Session key of the recipient
            message: Decrypted message to send
        """
        with self.lock:
            if recipient_key not in self.clients:
                print(f"[!] Recipient {recipient_key} not found or not connected")
                return
            
            recipient_conn, recipient_addr, recipient_shared_key, _, _, _, _ = self.clients[recipient_key]
        
        # Encrypt and send message character by character to recipient
        try:
            for char_index, char in enumerate(message):
                encrypted_char = self.encrypt_char_for_recipient(recipient_shared_key, char, char_index)
                recipient_conn.sendall(encrypted_char.encode())
                # Wait for ACK from recipient with timeout
                recipient_conn.settimeout(2.0)  # 2 second timeout
                try:
                    ack = recipient_conn.recv(3)
                    if ack != b"ACK":
                        print(f"[!] Failed to get ACK from recipient")
                        break
                except socket.timeout:
                    print(f"[!] Timeout waiting for ACK from recipient")
                    break
                except (ConnectionError, OSError):
                    print(f"[!] Connection error while waiting for ACK")
                    break
                finally:
                    recipient_conn.settimeout(None)  # Reset timeout
                time.sleep(random.uniform(0.05, 0.15))
            
            # Send end-of-message marker
            recipient_conn.sendall(b"MSG_END")
            print(f"[+] Message routed to recipient {recipient_key}")
        except (ConnectionError, OSError) as e:
            print(f"[!] Failed to route message to recipient: {e}")
        except Exception as e:
            print(f"[!] Error routing message: {e}")

    def random_message_loop(self, session_key):
        """
        Continuously send random messages to obfuscate traffic.
        
        Args:
            session_key: Client session key
        """
        while session_key in self.clients:
            try:
                with self.lock:
                    if session_key not in self.clients:
                        break
                    conn, _, shared_key, _, _, _, _ = self.clients[session_key]
                self.send_random_message(conn, shared_key)
                time.sleep(random.uniform(0.1, 0.5))
            except (ConnectionError, OSError):
                # Connection closed, exit loop
                break
            except Exception:
                # Other errors, continue but with delay
                time.sleep(0.5)

    def handle_client(self, conn, addr, sender_key, recipient_key, initial_buffer=b''):
        """
        Handle client connection: key exchange, message decryption, and cleanup.
        
        Args:
            conn: Client connection socket
            addr: Client address
            sender_key: Sender's session key
            recipient_key: Recipient's session key
            initial_buffer: Already received data buffer (may contain public key)
        """
        # Receive public key (sent after session keys)
        # Start with any data already in the buffer
        peer_public_key_bytes = initial_buffer
        peer_public_key = None
        
        # Try to parse from initial buffer first
        if peer_public_key_bytes:
            try:
                peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
            except ValueError:
                pass  # Need more data
        
        # If not parsed yet, receive more data
        while peer_public_key is None:
            chunk = conn.recv(1024)
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
        conn.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        shared_key = self.derive_shared_key(peer_public_key)
        # Register client as waiting to receive messages
        with self.lock:
            self.clients[sender_key] = (conn, addr, shared_key, 0, time.time(), recipient_key, True)

        # Start thread for sending random messages
        threading.Thread(
            target=self.random_message_loop,
            args=(sender_key,),
            daemon=True
        ).start()

        message = ""
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    # Connection closed by sender - route message immediately
                    if message and recipient_key:
                        print(f"[!] Message received from {sender_key} to {recipient_key}: {message}")
                        # Route message in a separate thread to avoid blocking
                        threading.Thread(
                            target=self.route_message_to_recipient,
                            args=(sender_key, recipient_key, message),
                            daemon=True
                        ).start()
                    break
                encrypted_char = data.decode()
                with self.lock:
                    if sender_key not in self.clients:
                        break
                    conn, _, shared_key, char_index, _, recipient_key, _ = self.clients[sender_key]
                try:
                    decrypted_char = self.decrypt_char(shared_key, encrypted_char, char_index)
                    message += decrypted_char
                    conn.sendall(b"ACK")
                    with self.lock:
                        self.clients[sender_key] = (conn, addr, shared_key, char_index + 1, time.time(), recipient_key, False)
                except (ValueError, TypeError, Exception):
                    # If decryption fails (random message or invalid data), just send ACK
                    # This allows random obfuscation messages to pass through
                    try:
                        conn.sendall(b"ACK")
                    except (ConnectionError, OSError):
                        break
        except (ConnectionError, OSError):
            # Connection was closed by client - route message if we have one
            if message and recipient_key:
                print(f"[!] Message received from {sender_key} to {recipient_key}: {message}")
                # Route message in a separate thread to avoid blocking
                threading.Thread(
                    target=self.route_message_to_recipient,
                    args=(sender_key, recipient_key, message),
                    daemon=True
                ).start()
        finally:
            print(f"[!] Connection closed with {addr}")
            with self.lock:
                if sender_key in self.clients:
                    del self.clients[sender_key]

    def start(self):
        """
        Start the server and listen for incoming connections.
        """
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"[*] KARA Server listening on {self.host}:{self.port}")
        print("[*] Waiting for clients with session keys...")
        while True:
            conn, addr = self.server_socket.accept()
            # Receive data line by line
            buffer = b''
            sender_key = None
            recipient_key = None
            
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                buffer += data
                # Look for two newlines (session keys)
                newline_count = buffer.count(b'\n')
                if newline_count >= 2:
                    # Split by first two newlines
                    parts = buffer.split(b'\n', 2)
                    sender_key = parts[0].decode().strip()
                    recipient_key = parts[1].decode().strip()
                    # Remaining data (if any) is the start of public key
                    buffer = parts[2] if len(parts) > 2 else b''
                    break
            
            if sender_key:
                print(f"[+] New connection from {addr}")
                print(f"    Sender session key: {sender_key}")
                if recipient_key:
                    print(f"    Recipient session key: {recipient_key}")
                else:
                    print(f"    Mode: Receiving messages (no recipient specified)")
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr, sender_key, recipient_key, buffer),
                    daemon=True
                ).start()
            else:
                print(f"[!] Failed to receive session keys from {addr}")
                conn.close()


def main():
    """Main entry point for KARA server."""
    host = os.getenv('KARA_HOST', '127.0.0.1')
    port = int(os.getenv('KARA_PORT', '65432'))
    server = KARAServer(host=host, port=port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    except Exception as e:
        print(f"[!] Server error: {e}")


if __name__ == "__main__":
    main()
