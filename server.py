# server.py - JustUs Secret Chat Server
# Complete WebSocket server with all features

import asyncio
import json
import hashlib
import secrets
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass
import logging

from websockets.exceptions import ConnectionClosed
import bcrypt
import jwt
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===============================
# CONFIGURATION
# ===============================

class Config:
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", 8080))
    
    # Security
    JWT_SECRET = os.environ.get("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 24
    
    # Encryption
    PEPPER = os.environ.get("PEPPER", "justus-secret-pepper-change-this")
    
    # Redis (for production)
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379
    REDIS_DB = 0
    
    # Message settings
    MAX_MESSAGE_SIZE = 4096  # bytes
    MESSAGE_RETENTION_DAYS = 7  # Auto-delete messages after 7 days
    TYPING_TIMEOUT = 3  # seconds
    
    # Rate limiting
    MAX_MESSAGES_PER_MINUTE = 60
    MAX_CONNECTIONS_PER_IP = 5
    
    # Self-destruct
    SELF_DESTRUCT_OPTIONS = [5, 10, 30, 60, 300]
    
    # Database
    DATABASE_PATH = "justus.db"

# ===============================
# DATA MODELS
# ===============================

@dataclass
class User:
    username: str
    password_hash: str
    public_key: str
    created_at: datetime
    last_seen: datetime
    is_active: bool = True
    decoy_pin: Optional[str] = None
    
@dataclass
class Message:
    id: str
    sender: str
    recipient: str
    content_encrypted: str
    timestamp: datetime
    status: str  # 'sent', 'delivered', 'read'
    self_destruct_seconds: int = 0
    deleted_at: Optional[datetime] = None

@dataclass
class Session:
    token: str
    username: str
    created_at: datetime
    expires_at: datetime
    ip_address: str

@dataclass
class TypingStatus:
    username: str
    is_typing: bool
    last_update: datetime

# ===============================
# DATABASE MANAGER
# ===============================

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Users table
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    decoy_pin TEXT
                );
                
                -- Messages table
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content_encrypted TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'sent',
                    self_destruct_seconds INTEGER DEFAULT 0,
                    deleted_at TIMESTAMP,
                    FOREIGN KEY (sender) REFERENCES users(username),
                    FOREIGN KEY (recipient) REFERENCES users(username)
                );
                
                -- Sessions table
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    FOREIGN KEY (username) REFERENCES users(username)
                );
                
                -- Active connections (in-memory, but we'll persist for recovery)
                CREATE TABLE IF NOT EXISTS active_connections (
                    username TEXT PRIMARY KEY,
                    connected_at TIMESTAMP NOT NULL,
                    last_heartbeat TIMESTAMP NOT NULL
                );
                
                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
                CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
                CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
                
                -- Cleanup old messages trigger
                CREATE TRIGGER IF NOT EXISTS cleanup_old_messages
                AFTER INSERT ON messages
                BEGIN
                    DELETE FROM messages 
                    WHERE julianday('now') - julianday(timestamp) > 7;
                END;
            """)
            logger.info("Database initialized successfully")
    
    def create_user(self, user: User) -> bool:
        """Create a new user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, public_key, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (user.username, user.password_hash, user.public_key, user.created_at, user.last_seen)
                )
            logger.info(f"User created: {user.username}")
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"User already exists: {user.username}")
            return False
    
    def get_user(self, username: str) -> Optional[User]:
        """Retrieve user by username"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                return User(
                    username=row['username'],
                    password_hash=row['password_hash'],
                    public_key=row['public_key'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    last_seen=datetime.fromisoformat(row['last_seen']),
                    is_active=bool(row['is_active']),
                    decoy_pin=row['decoy_pin']
                )
        return None
    
    def update_public_key(self, username: str, public_key: str):
        """Update user's public key"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET public_key = ? WHERE username = ?",
                (public_key, username)
            )
    
    def update_last_seen(self, username: str):
        """Update user's last seen timestamp"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET last_seen = ? WHERE username = ?",
                (datetime.now().isoformat(), username)
            )
    
    def save_message(self, message: Message) -> bool:
        """Save a message to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT INTO messages 
                       (id, sender, recipient, content_encrypted, timestamp, status, self_destruct_seconds) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (message.id, message.sender, message.recipient, 
                     message.content_encrypted, message.timestamp.isoformat(),
                     message.status, message.self_destruct_seconds)
                )
            return True
        except Exception as e:
            logger.error(f"Error saving message: {e}")
            return False
    
    def update_message_status(self, message_id: str, status: str):
        """Update message delivery/read status"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE messages SET status = ? WHERE id = ?",
                (status, message_id)
            )
    
    def delete_message(self, message_id: str):
        """Soft delete a message"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE messages SET deleted_at = ? WHERE id = ?",
                (datetime.now().isoformat(), message_id)
            )
    
    def get_undelivered_messages(self, username: str) -> list:
        """Get undelivered messages for a user"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """SELECT * FROM messages 
                   WHERE recipient = ? AND status IN ('sent', 'delivered') 
                   AND deleted_at IS NULL
                   ORDER BY timestamp ASC""",
                (username,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def create_session(self, session: Session) -> bool:
        """Create a new session"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO sessions (token, username, created_at, expires_at, ip_address) VALUES (?, ?, ?, ?, ?)",
                    (session.token, session.username, session.created_at.isoformat(),
                     session.expires_at.isoformat(), session.ip_address)
                )
            return True
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False
    
    def validate_session(self, token: str) -> Optional[str]:
        """Validate session token and return username"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT username, expires_at FROM sessions WHERE token = ?",
                (token,)
            )
            row = cursor.fetchone()
            if row:
                expires_at = datetime.fromisoformat(row[1])
                if expires_at > datetime.now():
                    return row[0]
        return None
    
    def delete_session(self, token: str):
        """Delete a session (logout)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
    
    def set_decoy_pin(self, username: str, pin: str):
        """Set decoy mode PIN for a user"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET decoy_pin = ? WHERE username = ?",
                (hashlib.sha256(pin.encode()).hexdigest(), username)
            )
    
    def delete_user(self, username: str):
        """Delete user and all associated data"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM messages WHERE sender = ? OR recipient = ?", (username, username))
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            conn.execute("DELETE FROM active_connections WHERE username = ?", (username,))
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
    
    def update_password(self, username: str, new_password_hash: str):
        """Update user's password hash"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_password_hash, username)
            )
    
    def verify_decoy_pin(self, username: str, pin: str) -> bool:
        """Verify decoy mode PIN"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT decoy_pin FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                return row[0] == hashlib.sha256(pin.encode()).hexdigest()
        return False

# ===============================
# AUTHENTICATION MANAGER
# ===============================

class AuthManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt and pepper"""
        peppered = password + Config.PEPPER
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(peppered.encode(), salt).decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password"""
        peppered = password + Config.PEPPER
        return bcrypt.checkpw(peppered.encode(), hashed.encode())
    
    def generate_token(self, username: str, ip_address: str) -> str:
        """Generate JWT token for session"""
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS),
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(8),
            'ip': ip_address
        }
        return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)
    
    def verify_token(self, token: str) -> Optional[str]:
        """Verify JWT token and return username"""
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            return payload.get('username')
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
        return None
    
    async def register_user(self, username: str, password: str, public_key: str) -> dict:
        """Register a new user"""
        # Validate username
        if not username or len(username) < 3 or len(username) > 20:
            return {'success': False, 'error': 'Username must be 3-20 characters'}
        
        # Validate password
        if len(password) < 6:
            return {'success': False, 'error': 'Password must be at least 6 characters'}
        
        # Check if user exists
        if self.db.get_user(username):
            return {'success': False, 'error': 'Username already exists'}
        
        # Create user
        user = User(
            username=username,
            password_hash=self.hash_password(password),
            public_key=public_key,
            created_at=datetime.now(),
            last_seen=datetime.now()
        )
        
        if self.db.create_user(user):
            token = self.generate_token(username, "")
            session = Session(
                token=token,
                username=username,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=Config.JWT_EXPIRY_HOURS),
                ip_address=""
            )
            self.db.create_session(session)
            return {'success': True, 'token': token, 'username': username}
        
        return {'success': False, 'error': 'Registration failed'}
    
    async def login_user(self, username: str, password: str) -> dict:
        """Login existing user"""
        user = self.db.get_user(username)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        if not self.verify_password(password, user.password_hash):
            return {'success': False, 'error': 'Invalid password'}
        
        # Generate new token
        token = self.generate_token(username, "")
        session = Session(
            token=token,
            username=username,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=Config.JWT_EXPIRY_HOURS),
            ip_address=""
        )
        self.db.create_session(session)
        
        return {
            'success': True, 
            'token': token, 
            'username': username,
            'public_key': user.public_key
        }
    
    async def delete_user(self, token: str, password: str) -> dict:
        """Delete user account — requires auth token + password confirmation"""
        username = self.verify_token(token)
        if not username:
            return {'success': False, 'error': 'Invalid or expired token'}
        user = self.db.get_user(username)
        if not user:
            return {'success': False, 'error': 'User not found'}
        if not self.verify_password(password, user.password_hash):
            return {'success': False, 'error': 'Invalid password'}
        self.db.delete_user(username)
        return {'success': True}
    
    async def reset_password(self, token: str, old_password: str, new_password: str) -> dict:
        """Reset password — requires auth token + old password"""
        username = self.verify_token(token)
        if not username:
            return {'success': False, 'error': 'Invalid or expired token'}
        user = self.db.get_user(username)
        if not user:
            return {'success': False, 'error': 'User not found'}
        if not self.verify_password(old_password, user.password_hash):
            return {'success': False, 'error': 'Invalid current password'}
        if len(new_password) < 6:
            return {'success': False, 'error': 'New password must be at least 6 characters'}
        new_hash = self.hash_password(new_password)
        self.db.update_password(username, new_hash)
        return {'success': True}


# ===============================
# MESSAGE PROCESSOR
# ===============================

class MessageProcessor:
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def create_message(self, sender: str, recipient: str, content_encrypted: str, 
                       self_destruct: int = 0) -> Message:
        """Create a new message object"""
        return Message(
            id=secrets.token_urlsafe(16),
            sender=sender,
            recipient=recipient,
            content_encrypted=content_encrypted,
            timestamp=datetime.now(),
            status='sent',
            self_destruct_seconds=self_destruct
        )
    
    async def process_undelivered_messages(self, username: str, websocket):
        """Send undelivered messages to user"""
        messages = self.db.get_undelivered_messages(username)
        for msg in messages:
            try:
                await websocket.send(json.dumps({
                    'type': 'message',
                    'id': msg['id'],
                    'content': msg['content_encrypted'],
                    'sender': msg['sender'],
                    'timestamp': msg['timestamp'],
                    'self_destruct': msg['self_destruct_seconds']
                }))
                # Update status to delivered
                self.db.update_message_status(msg['id'], 'delivered')
            except Exception as e:
                logger.error(f"Error sending undelivered message: {e}")



# ===============================
# WEBSOCKET SERVER
# ===============================

class WebSocketServer:
    def __init__(self, auth_manager: AuthManager, db: DatabaseManager, message_processor: MessageProcessor):
        self.auth_manager = auth_manager
        self.db = db
        self.message_processor = message_processor
        self.connections: Dict[str, Any] = {}
        self.typing_status: Dict[str, TypingStatus] = {}
        self.ip_connections: Dict[str, int] = {}
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle both HTTP and WebSocket connections on the same port"""
        try:
            data = await reader.read(4096)
            if not data:
                return
            request_text = data.decode('utf-8', errors='replace')
            lines = request_text.split('\r\n')
            first_line = lines[0] if lines else ''
            parts = first_line.split(' ') if first_line else []
            method = parts[0] if len(parts) > 0 else ''
            path = parts[1] if len(parts) > 1 else '/'

            # Handle non-GET methods
            if method == 'HEAD':
                body = 'OK'
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                writer.write(response.encode())
                await writer.drain()
                writer.close()
                return
            elif method == 'POST':
                await self._handle_post(writer, path, request_text)
                return
            elif method not in ('GET',):
                body = 'Method Not Allowed'
                response = f"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                writer.write(response.encode())
                await writer.drain()
                writer.close()
                return

            # Handle HTTP API endpoints (non-WebSocket GET)
            is_ws = 'upgrade: websocket' in request_text.lower()
            if not is_ws:
                if path == '/api/health':
                    body = json.dumps({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    writer.write(response.encode())
                    await writer.drain()
                else:
                    body = json.dumps({'error': 'Not found'})
                    response = f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                    writer.write(response.encode())
                    await writer.drain()
                writer.close()
                return

            # WebSocket connection - put data back and let websockets handle
            reader.feed_data(data)
            from websockets.asyncio.server import ServerConnection
            conn = ServerConnection(
                reader=reader,
                writer=writer,
                max_size=Config.MAX_MESSAGE_SIZE,
                ping_interval=20,
                ping_timeout=60,
            )
            await conn.handshake()
            await self.handler(conn, path)

        except Exception as e:
            logger.debug(f"Connection handler error: {e}")
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_post(self, writer, path: str, request_text: str):
        """Handle POST requests to the REST API"""
        try:
            body_start = request_text.find('\r\n\r\n')
            if body_start == -1:
                body = json.dumps({'success': False, 'error': 'Bad request'})
                response = f"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                writer.write(response.encode())
                await writer.drain()
                writer.close()
                return

            body_json = json.loads(request_text[body_start + 4:])

            if path == '/api/register':
                result = await self.auth_manager.register_user(
                    body_json.get('username', ''),
                    body_json.get('password', ''),
                    body_json.get('public_key', '')
                )
            elif path == '/api/login':
                result = await self.auth_manager.login_user(
                    body_json.get('username', ''),
                    body_json.get('password', '')
                )
            elif path == '/api/delete_user':
                result = await self.auth_manager.delete_user(
                    body_json.get('token', ''),
                    body_json.get('password', '')
                )
            elif path == '/api/reset_password':
                result = await self.auth_manager.reset_password(
                    body_json.get('token', ''),
                    body_json.get('old_password', ''),
                    body_json.get('new_password', '')
                )
            else:
                result = {'success': False, 'error': 'Not found'}

            status = 200 if result.get('success') else 400
            body = json.dumps(result)
            response = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            writer.write(response.encode())
            await writer.drain()
        except json.JSONDecodeError:
            body = json.dumps({'success': False, 'error': 'Invalid JSON'})
            response = f"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            writer.write(response.encode())
            await writer.drain()
        except Exception as e:
            logger.error(f"POST handler error: {e}")
            body = json.dumps({'success': False, 'error': 'Internal error'})
            response = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            writer.write(response.encode())
            await writer.drain()
        finally:
            writer.close()

    async def process_request(self, path, request_headers):
        return None  # All request handling is in handle_connection now

    async def handler(self, websocket, path: str):
        """Handle WebSocket connections"""
        client_ip = websocket.remote_address[0]
        
        # Rate limit by IP
        if self.ip_connections.get(client_ip, 0) >= Config.MAX_CONNECTIONS_PER_IP:
            logger.warning(f"Too many connections from IP: {client_ip}")
            await websocket.close(1008, "Too many connections")
            return
        
        # Authenticate
        token = None
        username = None
        
        # Get token from query string
        if '?' in path:
            query = path.split('?', 1)[1]
            params = dict(param.split('=') for param in query.split('&') if '=' in param)
            token = params.get('token')
            username = params.get('user')
        
        # Validate token
        if not token or not username:
            await websocket.close(1008, "Authentication required")
            return
        
        # Verify session — try DB first, fall back to JWT
        stored_username = self.db.validate_session(token)
        if not stored_username:
            stored_username = self.auth_manager.verify_token(token)
        if not stored_username or stored_username != username:
            await websocket.close(1008, "Invalid session")
            return
        
        # Check if user is already connected
        if username in self.connections:
            logger.warning(f"User already connected: {username}")
            await websocket.close(1008, "Already connected")
            return
        
        # Add connection
        self.connections[username] = websocket
        self.ip_connections[client_ip] = self.ip_connections.get(client_ip, 0) + 1
        self.db.update_last_seen(username)
        
        logger.info(f"User connected: {username} from {client_ip}")
        
        # Send undelivered messages
        await self.message_processor.process_undelivered_messages(username, websocket)
        
        # Notify friends that user is online
        await self.broadcast_status(username, "online")
        
        try:
            async for message in websocket:
                await self.process_message(username, message)
                
        except ConnectionClosed:
            logger.info(f"User disconnected: {username}")
        except Exception as e:
            logger.error(f"Error handling user {username}: {e}")
        finally:
            # Cleanup
            self.connections.pop(username, None)
            self.ip_connections[client_ip] = max(0, self.ip_connections.get(client_ip, 0) - 1)
            self.typing_status.pop(username, None)
            
            # Notify friends that user is offline
            await self.broadcast_status(username, "offline")
    
    async def process_message(self, sender: str, message: str):
        """Process incoming WebSocket message"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'message':
                await self.handle_chat_message(sender, data)
            elif msg_type == 'typing':
                await self.handle_typing_indicator(sender, data)
            elif msg_type == 'delivered':
                await self.handle_delivery_receipt(data)
            elif msg_type == 'read':
                await self.handle_read_receipt(data)
            elif msg_type == 'key_exchange':
                await self.handle_key_exchange(sender, data)
            elif msg_type == 'ping':
                await self.handle_ping(sender, data)
            else:
                logger.warning(f"Unknown message type from {sender}: {msg_type}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {sender}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
    
    async def handle_chat_message(self, sender: str, data: dict):
        """Handle chat message"""
        recipient = data.get('recipient')
        content = data.get('content')
        message_id = data.get('id')
        self_destruct = data.get('selfDestruct', 0)
        
        if not recipient or not content:
            return
        
        # Save message to database
        message = self.message_processor.create_message(sender, recipient, content, self_destruct)
        self.db.save_message(message)
        
        # Send to recipient if online
        if recipient in self.connections:
            try:
                await self.connections[recipient].send(json.dumps({
                    'type': 'message',
                    'id': message.id,
                    'content': content,
                    'sender': sender,
                    'timestamp': message.timestamp.isoformat(),
                    'self_destruct': self_destruct
                }))
                # Update status to delivered
                self.db.update_message_status(message.id, 'delivered')
                
                # Send delivery receipt to sender
                if sender in self.connections:
                    await self.connections[sender].send(json.dumps({
                        'type': 'delivered',
                        'messageId': message.id
                    }))
            except Exception as e:
                logger.error(f"Error sending message to {recipient}: {e}")
    
    async def handle_typing_indicator(self, sender: str, data: dict):
        """Handle typing indicator"""
        is_typing = data.get('isTyping', False)
        
        # Store typing status
        self.typing_status[sender] = TypingStatus(
            username=sender,
            is_typing=is_typing,
            last_update=datetime.now()
        )
        
        # Broadcast to all connected users (or specific recipient)
        for username, ws in self.connections.items():
            if username != sender:
                try:
                    await ws.send(json.dumps({
                        'type': 'typing',
                        'sender': sender,
                        'isTyping': is_typing
                    }))
                except Exception as e:
                    logger.error(f"Error sending typing indicator: {e}")
    
    async def handle_delivery_receipt(self, data: dict):
        """Handle delivery receipt"""
        message_id = data.get('messageId')
        if message_id:
            self.db.update_message_status(message_id, 'delivered')
    
    async def handle_read_receipt(self, data: dict):
        """Handle read receipt"""
        message_id = data.get('messageId')
        if message_id:
            self.db.update_message_status(message_id, 'read')
            
            # Forward read receipt to sender
            # (You'd need to know who the sender is from the message)
            pass
    
    async def handle_key_exchange(self, sender: str, data: dict):
        """Handle encryption key exchange"""
        recipient = data.get('recipient')
        public_key = data.get('publicKey')
        
        if recipient and public_key and recipient in self.connections:
            await self.connections[recipient].send(json.dumps({
                'type': 'key_exchange',
                'sender': sender,
                'publicKey': public_key
            }))
    
    async def handle_ping(self, sender: str, data: dict):
        """Handle ping/pong for connection health"""
        if sender in self.connections:
            await self.connections[sender].send(json.dumps({
                'type': 'pong',
                'timestamp': datetime.now().isoformat()
            }))
    
    async def broadcast_status(self, username: str, status: str):
        """Broadcast user online/offline status"""
        for user, ws in self.connections.items():
            if user != username:
                try:
                    await ws.send(json.dumps({
                        'type': 'status',
                        'user': username,
                        'status': status
                    }))
                except Exception as e:
                    logger.error(f"Error broadcasting status: {e}")
    
    async def cleanup_typing_indicators(self):
        """Remove stale typing indicators"""
        while True:
            await asyncio.sleep(5)
            now = datetime.now()
            to_remove = []
            for username, status in self.typing_status.items():
                if (now - status.last_update).seconds > Config.TYPING_TIMEOUT:
                    to_remove.append(username)
            
            for username in to_remove:
                del self.typing_status[username]
                # Broadcast that user stopped typing
                for ws in self.connections.values():
                    await ws.send(json.dumps({
                        'type': 'typing',
                        'sender': username,
                        'isTyping': False
                    }))

# ===============================
# MAIN SERVER
# ===============================

class JustUsServer:
    def __init__(self):
        self.db = DatabaseManager(Config.DATABASE_PATH)
        self.auth_manager = AuthManager(self.db)
        self.message_processor = MessageProcessor(self.db)
        self.ws_server = WebSocketServer(self.auth_manager, self.db, self.message_processor)
        self.scheduler = AsyncIOScheduler()
    
    async def cleanup_tasks(self):
        """Schedule periodic cleanup tasks"""
        # Clean expired sessions every hour
        self.scheduler.add_job(
            self.db.cleanup_expired_sessions,
            'interval',
            hours=1
        )
        
        # Clean typing indicators
        self.scheduler.add_job(
            self.ws_server.cleanup_typing_indicators,
            'interval',
            seconds=10
        )
        
        self.scheduler.start()
    
    async def start_server(self):
        """Start combined WebSocket + HTTP API server using raw TCP server"""
        server = await asyncio.start_server(
            self.ws_server.handle_connection,
            Config.HOST,
            Config.PORT
        )
        logger.info(f"Server running on 0.0.0.0:{Config.PORT}")
        async with server:
            await server.serve_forever()
    
    async def run(self):
        """Start server"""
        logger.info("Starting JustUs Secret Chat Server...")
        await self.cleanup_tasks()
        try:
            await self.start_server()
        except KeyboardInterrupt:
            logger.info("Shutting down servers...")
        finally:
            self.scheduler.shutdown()

# ===============================
# RUN SERVER
# ===============================

if __name__ == "__main__":
    server = JustUsServer()
    asyncio.run(server.run())
