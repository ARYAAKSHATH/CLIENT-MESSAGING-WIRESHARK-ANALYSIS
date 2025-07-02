#!/usr/bin/env python3
"""
Advanced Messaging Server
B205 Computer Networks - Individual Final Project
Client-Server Architecture Implementation

Features:
- Real-time messaging
- File/photo transfer
- User authentication
- Contact management
- Multi-client support
"""

import socket
import threading
import json
import os
import base64
import hashlib
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

class DatabaseManager:
    """Handles all database operations for user management and message storage"""
    
    def __init__(self, db_path: str = "messaging_server.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP,
                    is_online BOOLEAN DEFAULT 0
                )
            ''')
            
            # Messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    recipient_id INTEGER,
                    message_type TEXT DEFAULT 'text',
                    content TEXT,
                    file_data BLOB,
                    filename TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (recipient_id) REFERENCES users (id)
                )
            ''')
            
            # Contacts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    contact_id INTEGER,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (contact_id) REFERENCES users (id),
                    UNIQUE(user_id, contact_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Database initialization error: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username: str, password: str, email: str = None) -> bool:
        """Register a new user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = self.hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, password_hash, email)
            )
            
            conn.commit()
            conn.close()
            logging.info(f"User {username} registered successfully")
            return True
            
        except sqlite3.IntegrityError:
            logging.warning(f"Registration failed: Username {username} already exists")
            return False
        except Exception as e:
            logging.error(f"Registration error: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> Optional[int]:
        """Authenticate user and return user ID if successful"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = self.hash_password(password)
            cursor.execute(
                "SELECT id FROM users WHERE username = ? AND password_hash = ?",
                (username, password_hash)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                logging.info(f"User {username} authenticated successfully")
                return result[0]
            else:
                logging.warning(f"Authentication failed for user {username}")
                return None
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user information by ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, username, email, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'id': result[0],
                    'username': result[1],
                    'email': result[2],
                    'created_at': result[3]
                }
            return None
            
        except Exception as e:
            logging.error(f"Error fetching user: {e}")
            return None
    
    def save_message(self, sender_id: int, recipient_id: int, 
                    message_type: str, content: str = None, 
                    file_data: bytes = None, filename: str = None) -> bool:
        """Save message to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO messages (sender_id, recipient_id, message_type, 
                                    content, file_data, filename)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sender_id, recipient_id, message_type, content, file_data, filename))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logging.error(f"Error saving message: {e}")
            return False


class MessagingServer:
    """Main server class handling client connections and message routing"""
    
    def __init__(self, host: str = 'localhost', port: int = 9999):
        self.host = host
        self.port = port
        self.clients: Dict[int, socket.socket] = {}  # user_id -> socket
        self.client_usernames: Dict[int, str] = {}  # user_id -> username
        self.db = DatabaseManager()
        self.server_socket = None
        self.running = False
    
    def start_server(self):
        """Start the messaging server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            
            logging.info(f"Server started on {self.host}:{self.port}")
            print(f"🚀 Messaging Server running on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logging.info(f"New connection from {client_address}")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logging.error(f"Socket error: {e}")
                    
        except Exception as e:
            logging.error(f"Server startup error: {e}")
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket: socket.socket, client_address):
        """Handle individual client connection"""
        user_id = None
        
        try:
            while self.running:
                # Receive message from client
                message_length = client_socket.recv(4)
                if not message_length:
                    break
                
                msg_len = int.from_bytes(message_length, byteorder='big')
                message_data = b''
                
                while len(message_data) < msg_len:
                    chunk = client_socket.recv(min(msg_len - len(message_data), 4096))
                    if not chunk:
                        break
                    message_data += chunk
                
                if len(message_data) != msg_len:
                    break
                
                try:
                    message = json.loads(message_data.decode('utf-8'))
                    response = self.process_message(message, user_id)
                    
                    # Update user_id if login was successful
                    if message.get('type') == 'login' and response.get('status') == 'success':
                        user_id = response.get('user_id')
                        self.clients[user_id] = client_socket
                        self.client_usernames[user_id] = message.get('username')
                    
                    # Send response
                    self.send_message(client_socket, response)
                    
                except json.JSONDecodeError:
                    logging.error("Invalid JSON received")
                    self.send_message(client_socket, {'type': 'error', 'message': 'Invalid JSON'})
                
        except Exception as e:
            logging.error(f"Client handler error: {e}")
        finally:
            # Clean up client connection
            if user_id and user_id in self.clients:
                del self.clients[user_id]
                del self.client_usernames[user_id]
            
            client_socket.close()
            logging.info(f"Connection closed for {client_address}")
    
    def process_message(self, message: Dict, user_id: Optional[int]) -> Dict:
        """Process incoming message and return response"""
        message_type = message.get('type')
        
        if message_type == 'register':
            return self.handle_registration(message)
        elif message_type == 'login':
            return self.handle_login(message)
        elif message_type == 'send_message':
            return self.handle_send_message(message, user_id)
        elif message_type == 'send_file':
            return self.handle_send_file(message, user_id)
        elif message_type == 'get_online_users':
            return self.handle_get_online_users()
        else:
            return {'type': 'error', 'message': 'Unknown message type'}
    
    def handle_registration(self, message: Dict) -> Dict:
        """Handle user registration"""
        username = message.get('username')
        password = message.get('password')
        email = message.get('email')
        
        if not username or not password:
            return {'type': 'error', 'message': 'Username and password required'}
        
        if self.db.register_user(username, password, email):
            return {'type': 'register_response', 'status': 'success'}
        else:
            return {'type': 'register_response', 'status': 'error', 
                   'message': 'Username already exists'}
    
    def handle_login(self, message: Dict) -> Dict:
        """Handle user login"""
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            return {'type': 'error', 'message': 'Username and password required'}
        
        user_id = self.db.authenticate_user(username, password)
        if user_id:
            return {
                'type': 'login_response', 
                'status': 'success', 
                'user_id': user_id,
                'username': username
            }
        else:
            return {'type': 'login_response', 'status': 'error', 
                   'message': 'Invalid credentials'}
    
    def handle_send_message(self, message: Dict, sender_id: int) -> Dict:
        """Handle text message sending"""
        if not sender_id:
            return {'type': 'error', 'message': 'Not authenticated'}
        
        recipient_username = message.get('recipient')
        content = message.get('content')
        
        if not recipient_username or not content:
            return {'type': 'error', 'message': 'Recipient and content required'}
        
        # Find recipient user ID
        recipient_id = self.find_user_id_by_username(recipient_username)
        if not recipient_id:
            return {'type': 'error', 'message': 'Recipient not found'}
        
        # Save message to database
        if self.db.save_message(sender_id, recipient_id, 'text', content):
            # Forward message to recipient if online
            if recipient_id in self.clients:
                forward_msg = {
                    'type': 'new_message',
                    'sender': self.client_usernames.get(sender_id, 'Unknown'),
                    'content': content,
                    'timestamp': datetime.now().isoformat()
                }
                self.send_message(self.clients[recipient_id], forward_msg)
            
            return {'type': 'send_response', 'status': 'success'}
        else:
            return {'type': 'send_response', 'status': 'error', 
                   'message': 'Failed to save message'}
    
    def handle_send_file(self, message: Dict, sender_id: int) -> Dict:
        """Handle file/photo sending"""
        if not sender_id:
            return {'type': 'error', 'message': 'Not authenticated'}
        
        recipient_username = message.get('recipient')
        filename = message.get('filename')
        file_data_b64 = message.get('file_data')
        
        if not all([recipient_username, filename, file_data_b64]):
            return {'type': 'error', 'message': 'Recipient, filename, and file data required'}
        
        try:
            file_data = base64.b64decode(file_data_b64)
        except Exception as e:
            return {'type': 'error', 'message': 'Invalid file data'}
        
        # Find recipient user ID
        recipient_id = self.find_user_id_by_username(recipient_username)
        if not recipient_id:
            return {'type': 'error', 'message': 'Recipient not found'}
        
        # Save file message to database
        if self.db.save_message(sender_id, recipient_id, 'file', 
                               filename, file_data, filename):
            # Forward file to recipient if online
            if recipient_id in self.clients:
                forward_msg = {
                    'type': 'new_file',
                    'sender': self.client_usernames.get(sender_id, 'Unknown'),
                    'filename': filename,
                    'file_data': file_data_b64,
                    'timestamp': datetime.now().isoformat()
                }
                self.send_message(self.clients[recipient_id], forward_msg)
            
            return {'type': 'send_response', 'status': 'success'}
        else:
            return {'type': 'send_response', 'status': 'error', 
                   'message': 'Failed to save file'}
    
    def handle_get_online_users(self) -> Dict:
        """Get list of online users"""
        online_users = list(self.client_usernames.values())
        return {
            'type': 'online_users_response',
            'users': online_users
        }
    
    def find_user_id_by_username(self, username: str) -> Optional[int]:
        """Find user ID by username"""
        for user_id, uname in self.client_usernames.items():
            if uname == username:
                return user_id
        return None
    
    def send_message(self, client_socket: socket.socket, message: Dict):
        """Send message to client"""
        try:
            message_data = json.dumps(message).encode('utf-8')
            message_length = len(message_data).to_bytes(4, byteorder='big')
            client_socket.send(message_length + message_data)
        except Exception as e:
            logging.error(f"Error sending message: {e}")
    
    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logging.info("Server stopped")


if __name__ == "__main__":
    server = MessagingServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
        server.stop_server()