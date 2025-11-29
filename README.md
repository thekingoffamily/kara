<div align="center">
  <img src="media/logo.png" alt="KARA Protocol Logo" width="400">
</div>

# **KARA Protocol**
**Keyed Anonymous Randomized Architecture**

A **high-security, anonymous, and randomized** messaging protocol designed for **end-to-end encrypted** communication with **no message persistence**. KARA ensures that every character is encrypted with a unique key, and the traffic is obfuscated with random noise to prevent analysis.

---

## **Features**
✅ **Per-Character Encryption** – Each character is encrypted with a unique key derived from **ECDH + HKDF**.
✅ **Random Traffic Obfuscation** – The server constantly sends random encrypted messages to mask real communication.
✅ **No Message Storage** – All data is kept in memory and discarded after transmission.
✅ **Session-Based Authentication** – Each session generates a **SHA-256 key** for manual verification.
✅ **Resistant to Replay Attacks** – Dynamic key updates and **ACK-based confirmation** prevent replay attacks.
✅ **Quantum-Resistant Ready** – Can be extended with **post-quantum cryptography** (e.g., Kyber, Dilithium).

---

## **How It Works**
1. **Session Key Exchange**
   - Each client generates a **unique SHA-256 session key** on startup.
   - Users manually verify keys before communication.

2. **Per-Character Encryption**
   - Every character is encrypted with a **unique key** derived from a shared secret.
   - Uses **AES-256-GCM** for encryption.

3. **Random Traffic Obfuscation**
   - The server **continuously sends random encrypted messages** to mask real traffic.
   - Clients ignore random messages and only process valid **ACK-confirmed** data.

4. **No Persistence**
   - Keys and messages are **never stored**—everything is discarded after transmission.

---

## **Installation**
1. **Clone the repository:**
   ```bash
   git clone https://github.com/thekingoffamily/kara.git
   cd kara
   ```

2. **Install dependencies:**
   ```bash
   pip install cryptography
   ```

---

## **Usage**

### **Option 1: Direct Python Execution**

#### **1. Start the Server**
```bash
python -m server.main
```
or
```bash
cd server && python main.py
```
- The server will listen for incoming connections and **continuously send random noise**.

#### **2. Run the Client**
```bash
python -m client.main
```
or
```bash
cd client && python main.py
```
- The client will generate a **SHA-256 session key** (displayed in the console).
- Enter the **recipient's session key** to establish a secure connection.
- Send messages **character by character** with per-symbol encryption.

### **Option 2: Docker Compose**

#### **Start Server and Client**
```bash
docker-compose up
```

#### **Start Only Server**
```bash
docker-compose up kara-server
```

#### **Run Client Separately**
```bash
docker-compose run --rm kara-client
```

### **Option 3: Individual Docker Containers**

#### **Build and Run Server**
```bash
docker build -f Dockerfile.server -t kara-server .
docker run -p 65432:65432 kara-server
```

#### **Build and Run Client**
```bash
docker build -f Dockerfile.client -t kara-client .
docker run -it --network host kara-client
```

---

## **Example Workflow**
1. **Alice runs the server:**
   ```bash
   python -m server.main
   ```
2. **Bob runs the client:**
   ```bash
   python -m client.main
   ```
   - Bob's session key: `a1b2c3...` (displayed in console).
3. **Alice runs another client:**
   ```bash
   python -m client.main
   ```
   - Alice enters Bob's session key (`a1b2c3...`).
4. **Alice sends a message:**
   ```
   Enter your message: Hello, Bob!
   ```
   - The message is **encrypted per character** and sent with random noise.

---

## **Security Considerations**
🔒 **No Logs** – No messages or keys are stored.
🔒 **Traffic Obfuscation** – Random messages make it hard to distinguish real communication.
🔒 **Manual Key Verification** – Users must verify session keys out-of-band (e.g., via phone).
🔒 **Resistant to MITM** – ECDH key exchange prevents man-in-the-middle attacks.

---

## **Future Improvements**
🔜 **Post-Quantum Cryptography** – Integrate **Kyber/Dilithium** for quantum resistance.
🔜 **GUI Support** – Add a **Tkinter/PyQt** interface for easier use.
🔜 **Group Chats** – Extend to support **multi-user encrypted sessions**.
🔜 **File Transfer** – Add **encrypted file sharing** (chunked + obfuscated).

---

## **License**
This project is licensed under the **MIT License** – see [`LICENSE`](LICENSE) for details.

---
**KARA: Where every character is a secret.** 🔐