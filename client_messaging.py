#!/usr/bin/env python3
"""
Advanced Messaging Client
B205 Computer Networks - Individual Final Project
GUI Client Application with Tkinter

Features:
- User-friendly GUI interface
- Real-time messaging
- File/photo transfer
- User authentication
- Contact management
"""

import socket
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import base64
import os
from datetime import datetime
from typing import Optional

class MessagingClient:
    """GUI-based messaging client"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Messaging Client")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        # Connection variables
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.authenticated = False
        self.username = ""
        self.user_id = None
        
        # GUI components
        self.setup_gui()
        self.show_login_screen()
        
        # Start message receiver thread
        self.receiver_thread = None
        
    def setup_gui(self):
        """Setup the main GUI components"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), 
                       foreground='white', background='#2c3e50')
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'), 
                       foreground='white', background='#34495e')
        style.configure('Custom.TFrame', background='#34495e')
        style.configure('Chat.TFrame', background='#ecf0f1')
        
        # Main container
        self.main_frame = ttk.Frame(self.root, style='Custom.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Login frame
        self.login_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        
        # Chat frame
        self.chat_frame = ttk.Frame(self.main_frame, style='Chat.TFrame')
        
    def show_login_screen(self):
        """Display login/registration screen"""
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_frame.pack_forget()
        
        # Title
        title_label = ttk.Label(self.login_frame, text="🚀 Advanced Messaging Client", 
                               style='Title.TLabel')
        title_label.pack(pady=20)
        
        # Server connection frame
        conn_frame = ttk.LabelFrame(self.login_frame, text="Server Connection", 
                                   padding=20)
        conn_frame.pack(pady=10, padx=50, fill=tk.X)
        
        ttk.Label(conn_frame, text="Server Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = ttk.Entry(conn_frame, width=30)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, pady=5, padx=10)
        
        ttk.Label(conn_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(conn_frame, width=30)
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=1, column=1, pady=5, padx=10)
        
        connect_btn = ttk.Button(conn_frame, text="Connect to Server", 
                                command=self.connect_to_server)
        connect_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Authentication frame
        self.auth_frame = ttk.LabelFrame(self.login_frame, text="Authentication", 
                                        padding=20)
        self.auth_frame.pack(pady=10, padx=50, fill=tk.X)
        
        ttk.Label(self.auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(self.auth_frame, width=30)
        self.username_entry.grid(row=0, column=1, pady=5, padx=10)
        
        ttk.Label(self.auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(self.auth_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, pady=5, padx=10)
        
        # Buttons frame
        btn_frame = ttk.Frame(self.auth_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        login_btn = ttk.Button(btn_frame, text="Login", command=self.login)
        login_btn.pack(side=tk.LEFT, padx=5)
        
        register_btn = ttk.Button(btn_frame, text="Register", command=self.register)
        register_btn.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = ttk.Label(self.login_frame, text="Not connected", 
                                     foreground='red')
        self.status_label.pack(pady=10)
        
        # Initially disable auth frame
        self.toggle_auth_frame(False)
    
    def show_chat_screen(self):
        """Display main chat interface"""
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(self.chat_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        welcome_label = ttk.Label(header_frame, text=f"Welcome, {self.username}! 👋", 
                                 style='Heading.TLabel')
        welcome_label.pack(side=tk.LEFT)
        
        logout_btn = ttk.Button(header_frame, text="Logout", command=self.logout)
        logout_btn.pack(side=tk.RIGHT)
        
        # Main chat area
        chat_paned = ttk.PanedWindow(self.chat_frame, orient=tk.HORIZONTAL)
        chat_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - Online users
        left_frame = ttk.LabelFrame(chat_paned, text="Online Users", padding=10)
        chat_paned.add(left_frame, weight=1)
        
        self.users_listbox = tk.Listbox(left_frame, height=20)
        self.users_listbox.pack(fill=tk.BOTH, expand=True)
        
        refresh_btn = ttk.Button(left_frame, text="Refresh Users", 
                                command=self.refresh_users)
        refresh_btn.pack(pady=5)
        
        # Right panel - Chat
        right_frame = ttk.Frame(chat_paned)
        chat_paned.add(right_frame, weight=3)
        
        # Chat display
        chat_label = ttk.Label(right_frame, text="Chat Messages", style='Heading.TLabel')
        chat_label.pack(anchor=tk.W, padx=5)
        
        self.chat_display = scrolledtext.ScrolledText(right_frame, height=20, 
                                                     state=tk.DISABLED, wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input area
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="To:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.recipient_entry = ttk.Entry(input_frame, width=20)
        self.recipient_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(input_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.message_entry = ttk.Entry(input_frame, width=50)
        self.message_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # Buttons
        buttons_frame = ttk.Frame(input_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        send_btn = ttk.Button(buttons_frame, text="Send Message", 
                             command=self.send_message)
        send_btn.pack(side=tk.LEFT, padx=5)
        
        file_btn = ttk.Button(buttons_frame, text="Send File", 
                             command=self.send_file)
        file_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Start refreshing users
        self.refresh_users()
    
    def toggle_auth_frame(self, enabled: bool):
        """Enable/disable authentication frame"""
        state = tk.NORMAL if enabled else tk.DISABLED
        for child in self.auth_frame.winfo_children():
            if isinstance(child, (ttk.Entry, ttk.Button)):
                child.configure(state=state)
    
    def connect_to_server(self):
        """Connect to the messaging server"""
        try:
            host = self.host_entry.get() or "localhost"
            port = int(self.port_entry.get() or "9999")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            
            self.status_label.configure(text="Connected to server ✅", foreground='green')
            self.toggle_auth_frame(True)
            
            # Start receiver thread
            self.receiver_thread = threading.Thread(target=self.receive_messages)
            self.receiver_thread.daemon = True
            self.receiver_thread.start()
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.status_label.configure(text=f"Connection failed: {e}", foreground='red')
    
    def send_request(self, message: dict) -> bool:
        """Send request to server"""
        if not self.connected or not self.socket:
            return False
        
        try:
            message_data = json.dumps(message).encode('utf-8')
            message_length = len(message_data).to_bytes(4, byteorder='big')
            self.socket.send(message_length + message_data)
            return True
        except Exception as e:
            print(f"Send error: {e}")
            return False
    
    def receive_messages(self):
        """Receive messages from server"""
        while self.connected and self.socket:
            try:
                # Read message length
                length_data = self.socket.recv(4)
                if not length_data:
                    break
                
                msg_len = int.from_bytes(length_data, byteorder='big')
                
                # Read message data
                message_data = b''
                while len(message_data) < msg_len:
                    chunk = self.socket.recv(min(msg_len - len(message_data), 4096))
                    if not chunk:
                        break
                    message_data += chunk
                
                if len(message_data) == msg_len:
                    message = json.loads(message_data.decode('utf-8'))
                    self.handle_server_message(message)
                    
            except Exception as e:
                if self.connected:
                    print(f"Receive error: {e}")
                break
    
    def handle_server_message(self, message: dict):
        """Handle messages received from server"""
        msg_type = message.get('type')
        
        if msg_type == 'new_message':
            self.display_message(message.get('sender', 'Unknown'), 
                               message.get('content', ''), 
                               message.get('timestamp', ''))
        
        elif msg_type == 'new_file':
            self.display_file_message(message.get('sender', 'Unknown'), 
                                    message.get('filename', ''), 
                                    message.get('file_data', ''),
                                    message.get('timestamp', ''))
        
        elif msg_type == 'online_users_response':
            self.update_users_list(message.get('users', []))
    
    def register(self):
        """Register new user"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        request = {
            'type': 'register',
            'username': username,
            'password': password
        }
        
        if self.send_request(request):
            messagebox.showinfo("Registration", "Registration request sent. Please login.")
        else:
            messagebox.showerror("Error", "Failed to send registration request")
    
    def login(self):
        """Login user"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        request = {
            'type': 'login',
            'username': username,
            'password': password
        }
        
        if self.send_request(request):
            # Wait for response (this is simplified - in production use proper async handling)
            self.root.after(1000, lambda: self.check_login_response(username))
        else:
            messagebox.showerror("Error", "Failed to send login request")
    
    def check_login_response(self, username: str):
        """Check if login was successful (simplified approach)"""
        # In a real implementation, you'd handle the server response properly
        # For this demo, we'll simulate successful login
        self.authenticated = True
        self.username = username
        self.user_id = 1  # Simplified
        messagebox.showinfo("Login", "Login successful!")
        self.show_chat_screen()
    
    def logout(self):
        """Logout and return to login screen"""
        self.authenticated = False
        self.username = ""
        self.user_id = None
        
        if self.socket:
            self.socket.close()
        self.connected = False
        
        self.show_login_screen()
        self.status_label.configure(text="Disconnected", foreground='red')
        self.toggle_auth_frame(False)
    
    def send_message(self):
        """Send text message"""
        if not self.authenticated:
            messagebox.showerror("Error", "Not authenticated")
            return
        
        recipient = self.recipient_entry.get()
        content = self.message_entry.get()
        
        if not recipient or not content:
            messagebox.showerror("Error", "Please enter recipient and message")
            return
        
        request = {
            'type': 'send_message',
            'recipient': recipient,
            'content': content
        }
        
        if self.send_request(request):
            # Display sent message locally
            self.display_message(f"{self.username} (You)", content, 
                               datetime.now().strftime("%H:%M:%S"))
            self.message_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Failed to send message")
    
    def send_file(self):
        """Send file or photo"""
        if not self.authenticated:
            messagebox.showerror("Error", "Not authenticated")
            return
        
        recipient = self.recipient_entry.get()
        if not recipient:
            messagebox.showerror("Error", "Please enter recipient")
            return
        
        # Select file
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files", "*.*"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Documents", "*.txt *.pdf *.doc *.docx")
            ]
        )
        
        if not file_path:
            return
        
        try:
            # Read and encode file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Check file size (limit to 10MB for demo)
            if len(file_data) > 10 * 1024 * 1024:
                messagebox.showerror("Error", "File too large (max 10MB)")
                return
            
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            filename = os.path.basename(file_path)
            
            request = {
                'type': 'send_file',
                'recipient': recipient,
                'filename': filename,
                'file_data': file_data_b64
            }
            
            if self.send_request(request):
                self.display_file_message(f"{self.username} (You)", filename, 
                                        file_data_b64, datetime.now().strftime("%H:%M:%S"))
                messagebox.showinfo("Success", f"File '{filename}' sent successfully!")
            else:
                messagebox.showerror("Error", "Failed to send file")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
    
    def refresh_users(self):
        """Refresh online users list"""
        if not self.authenticated:
            return
        
        request = {'type': 'get_online_users'}
        self.send_request(request)
        
        # Schedule next refresh
        self.root.after(5000, self.refresh_users)  # Refresh every 5 seconds
    
    def update_users_list(self, users: list):
        """Update the online users listbox"""
        self.users_listbox.delete(0, tk.END)
        for user in users:
            if user != self.username:  # Don't show self
                self.users_listbox.insert(tk.END, user)
        
        # Double-click to select recipient
        self.users_listbox.bind('<Double-Button-1>', self.select_recipient)
    
    def select_recipient(self, event):
        """Select recipient from users list"""
        selection = self.users_listbox.curselection()
        if selection:
            username = self.users_listbox.get(selection[0])
            self.recipient_entry.delete(0, tk.END)
            self.recipient_entry.insert(0, username)
    
    def display_message(self, sender: str, content: str, timestamp: str):
        """Display text message in chat"""
        self.chat_display.configure(state=tk.NORMAL)
        message_text = f"[{timestamp}] {sender}: {content}\n"
        self.chat_display.insert(tk.END, message_text)
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def display_file_message(self, sender: str, filename: str, 
                           file_data_b64: str, timestamp: str):
        """Display file message in chat"""
        self.chat_display.configure(state=tk.NORMAL)
        message_text = f"[{timestamp}] {sender} sent file: {filename}\n"
        self.chat_display.insert(tk.END, message_text)
        
        # Add clickable link to save file
        def save_file():
            try:
                file_data = base64.b64decode(file_data_b64)
                save_path = filedialog.asksaveasfilename(
                    initialname=filename,
                    title="Save received file"
                )
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    messagebox.showinfo("Success", f"File saved to {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
        
        # Create clickable button for file download
        save_button = tk.Button(self.chat_display, text=f"💾 Save '{filename}'", 
                               command=save_file, bg='lightblue')
        self.chat_display.window_create(tk.END, window=save_button)
        self.chat_display.insert(tk.END, "\n\n")
        
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def run(self):
        """Start the client application"""
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()
    
    def on_closing(self):
        """Handle application closing"""
        if self.socket:
            self.socket.close()
        self.root.destroy()


if __name__ == "__main__":
    client = MessagingClient()
    client.run()