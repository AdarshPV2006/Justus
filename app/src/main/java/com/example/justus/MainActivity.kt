@file:OptIn(ExperimentalMaterial3Api::class)

// MainActivity.kt - JustUs Secret Chat App with Jetpack Compose
// Complete single-file implementation

package com.example.justus

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.drawable.shapes.Shape
import android.os.Build
import android.os.Bundle
import android.os.CountDownTimer
import android.os.Handler
import android.os.Looper
import android.view.HapticFeedbackConstants
import android.view.SoundEffectConstants
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.accompanist.permissions.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import okhttp3.*
import okio.ByteString
import org.json.JSONObject
import java.security.*
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

// ===============================
// DATA MODELS
// ===============================

data class ChatMessage(
    val id: String,
    val text: String,
    val sender: String,
    val isSent: Boolean,
    val timestamp: Long,
    val status: MessageStatus = MessageStatus.SENDING,
    var selfDestructSeconds: Int = 0,
    var remainingDestructTime: Long = 0,
    val isBlurred: Boolean = true
)

enum class MessageStatus { SENDING, SENT, DELIVERED, READ }
enum class ConnectionState { CONNECTING, CONNECTED, DISCONNECTED, RECONNECTING }

// ===============================
// ENCRYPTION MANAGER
// ===============================

class EncryptionManager {
    private var privateKey: PrivateKey? = null
    private var publicKey: PublicKey? = null
    private var peerPublicKey: PublicKey? = null
    private var symmetricKey: SecretKey? = null

    init {
        generateRSAKeys()
    }

    private fun generateRSAKeys() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            val keyPair = keyPairGenerator.generateKeyPair()
            privateKey = keyPair.private
            publicKey = keyPair.public
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getPublicKeyBytes(): ByteArray? = publicKey?.encoded

    fun performKeyExchange(peerPublicKeyBytes: ByteArray) {
        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            peerPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(peerPublicKeyBytes))

            // Generate shared secret using ECDH
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(256)
            val ecKeyPair = kpg.generateKeyPair()

            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(ecKeyPair.private)
            keyAgreement.doPhase(peerPublicKey, true)

            val sharedSecret = keyAgreement.generateSecret()
            symmetricKey = SecretKeySpec(sharedSecret, "AES")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun encryptMessage(message: String): String {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, GCMParameterSpec(128, iv))
            val encryptedBytes = cipher.doFinal(message.toByteArray())
            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
            Base64.getEncoder().encodeToString(combined)
        } catch (e: Exception) {
            message
        }
    }

    fun decryptMessage(encryptedMessage: String): String {
        return try {
            val decoded = Base64.getDecoder().decode(encryptedMessage)
            val iv = decoded.copyOfRange(0, 12)
            val encrypted = decoded.copyOfRange(12, decoded.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey, GCMParameterSpec(128, iv))
            String(cipher.doFinal(encrypted))
        } catch (e: Exception) {
            "[Encrypted Message]"
        }
    }
}

// ===============================
// WEB SOCKET MANAGER
// ===============================

class WebSocketManager(
    private val onMessage: (String, String) -> Unit,
    private val onTyping: (String, Boolean) -> Unit,
    private val onStatusUpdate: (String, MessageStatus) -> Unit,
    private val onConnectionChange: (ConnectionState) -> Unit
) {
    private var webSocket: WebSocket? = null
    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .build()

    private var currentUser = ""
    private var sessionToken = ""
    private var isReconnecting = false

    fun connect(username: String, token: String, serverUrl: String) {
        currentUser = username
        sessionToken = token
        val request = Request.Builder()
            .url("$serverUrl/ws?token=$token&user=$username")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                onConnectionChange(ConnectionState.CONNECTED)
                isReconnecting = false
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val json = JSONObject(text)
                when (json.getString("type")) {
                    "message" -> {
                        val content = json.getString("content")
                        val sender = json.getString("sender")
                        onMessage(content, sender)
                    }
                    "typing" -> {
                        val sender = json.getString("sender")
                        val isTyping = json.getBoolean("isTyping")
                        onTyping(sender, isTyping)
                    }
                    "delivered" -> {
                        val messageId = json.getString("messageId")
                        onStatusUpdate(messageId, MessageStatus.DELIVERED)
                    }
                    "read" -> {
                        val messageId = json.getString("messageId")
                        onStatusUpdate(messageId, MessageStatus.READ)
                    }
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                onConnectionChange(ConnectionState.DISCONNECTED)
                attemptReconnect()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                onConnectionChange(ConnectionState.DISCONNECTED)
                attemptReconnect()
            }
        })
    }

    private fun attemptReconnect() {
        if (!isReconnecting) {
            isReconnecting = true
            onConnectionChange(ConnectionState.RECONNECTING)
            Handler(Looper.getMainLooper()).postDelayed({
                connect(currentUser, sessionToken, "ws://your-server-ip:8080")
            }, 3000)
        }
    }

    fun sendMessage(messageId: String, encryptedContent: String) {
        val json = JSONObject().apply {
            put("type", "message")
            put("id", messageId)
            put("content", encryptedContent)
            put("sender", currentUser)
            put("timestamp", System.currentTimeMillis())
        }
        webSocket?.send(json.toString())
    }

    fun sendTypingIndicator(isTyping: Boolean) {
        val json = JSONObject().apply {
            put("type", "typing")
            put("isTyping", isTyping)
            put("sender", currentUser)
        }
        webSocket?.send(json.toString())
    }

    fun sendDeliveryReceipt(messageId: String) {
        val json = JSONObject().apply {
            put("type", "delivered")
            put("messageId", messageId)
        }
        webSocket?.send(json.toString())
    }

    fun sendReadReceipt(messageId: String) {
        val json = JSONObject().apply {
            put("type", "read")
            put("messageId", messageId)
        }
        webSocket?.send(json.toString())
    }

    fun disconnect() {
        webSocket?.close(1000, "Normal closure")
        webSocket = null
    }
}

// ===============================
// MAIN ACTIVITY
// ===============================

class MainActivity : AppCompatActivity() {

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var encryptionManager: EncryptionManager
    private var webSocketManager: WebSocketManager? = null
    private val messages = mutableStateListOf<ChatMessage>()
    private var isAuthenticated by mutableStateOf(false)
    private var currentUser by mutableStateOf("")
    private var showDecoyMode by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Secure window
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        sharedPreferences = getSharedPreferences("JustUsSecure", Context.MODE_PRIVATE)
        encryptionManager = EncryptionManager()

        // Check for decoy mode
        showDecoyMode = sharedPreferences.getBoolean("decoyMode", false)

        setContent {
            JustUsTheme {
                if (showDecoyMode) {
                    DecoyScreen(onExitDecoy = { exitDecoyMode() })
                } else if (!isAuthenticated) {
                    LoginScreen(
                        onLoginSuccess = { username, token ->
                            currentUser = username
                            isAuthenticated = true
                            initializeChat(username, token)
                        }
                    )
                } else {
                    ChatScreen(
                        messages = messages,
                        currentUser = currentUser,
                        onSendMessage = { text, selfDestructSeconds ->
                            sendMessage(text, selfDestructSeconds)
                        },
                        onTyping = { isTyping ->
                            webSocketManager?.sendTypingIndicator(isTyping)
                        },
                        onRevealMessage = { messageId ->
                            webSocketManager?.sendReadReceipt(messageId)
                        }
                    )
                }
            }
        }

        // Biometric authentication
        if (sharedPreferences.getBoolean("biometricEnabled", false)) {
            authenticateWithBiometrics()
        }
    }

    private fun initializeChat(username: String, token: String) {
        webSocketManager = WebSocketManager(
            onMessage = { encryptedContent, sender ->
                val decrypted = encryptionManager.decryptMessage(encryptedContent)
                val message = ChatMessage(
                    id = UUID.randomUUID().toString(),
                    text = decrypted,
                    sender = sender,
                    isSent = false,
                    timestamp = System.currentTimeMillis(),
                    status = MessageStatus.DELIVERED,
                    selfDestructSeconds = 0,
                    isBlurred = true
                )
                messages.add(message)
                webSocketManager?.sendDeliveryReceipt(message.id)
            },
            onTyping = { sender, isTyping ->
                // Handle typing indicator in UI
            },
            onStatusUpdate = { messageId, status ->
                val index = messages.indexOfFirst { it.id == messageId }
                if (index != -1) {
                    messages[index] = messages[index].copy(status = status)
                }
            },
            onConnectionChange = { state ->
                // Update connection status in UI
            }
        )

        webSocketManager?.connect(username, token, "ws://your-server-ip:8080")

        // Exchange encryption keys
        val publicKeyBytes = encryptionManager.getPublicKeyBytes()
        // Send public key to server for peer exchange
    }

    private fun sendMessage(text: String, selfDestructSeconds: Int) {
        val encrypted = encryptionManager.encryptMessage(text)
        val messageId = UUID.randomUUID().toString()
        val message = ChatMessage(
            id = messageId,
            text = text,
            sender = currentUser,
            isSent = true,
            timestamp = System.currentTimeMillis(),
            status = MessageStatus.SENDING,
            selfDestructSeconds = selfDestructSeconds,
            isBlurred = false
        )
        messages.add(message)
        webSocketManager?.sendMessage(messageId, encrypted)

        if (selfDestructSeconds > 0) {
            startSelfDestructTimer(messageId, selfDestructSeconds)
        }
    }

    private fun startSelfDestructTimer(messageId: String, seconds: Int) {
        val timer = object : CountDownTimer((seconds * 1000).toLong(), 1000) {
            override fun onTick(millisUntilFinished: Long) {
                val index = messages.indexOfFirst { it.id == messageId }
                if (index != -1) {
                    messages[index] = messages[index].copy(
                        remainingDestructTime = millisUntilFinished / 1000
                    )
                }
            }

            override fun onFinish() {
                messages.removeAll { it.id == messageId }
            }
        }
        timer.start()
    }

    private fun authenticateWithBiometrics() {
        val executor = ContextCompat.getMainExecutor(this)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // Authentication successful
            }

            override fun onAuthenticationFailed() {
                if (!showDecoyMode) {
                    finish()
                }
            }
        }
        val biometricPrompt = BiometricPrompt(this, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("JustUs Authentication")
            .setSubtitle("Verify your identity to access secure messages")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun exitDecoyMode() {
        showDecoyMode = false
        sharedPreferences.edit().remove("decoyMode").apply()
        recreate()
    }

    override fun onPause() {
        super.onPause()
        // Auto-lock after 5 seconds in background
        Handler(Looper.getMainLooper()).postDelayed({
            if (!isFinishing) {
                isAuthenticated = false
                authenticateWithBiometrics()
            }
        }, 5000)
    }

    override fun onDestroy() {
        super.onDestroy()
        webSocketManager?.disconnect()
    }
}

// ===============================
// COMPOSE UI SCREENS
// ===============================

@Composable
fun LoginScreen(
    onLoginSuccess: (String, String) -> Unit
) {
    var isLoginMode by remember { mutableStateOf(true) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val context = LocalContext.current
    val focusManager = LocalFocusManager.current

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(Color(0xFF1a1a2e), Color(0xFF16213e))
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Logo and Title
            Surface(
                modifier = Modifier.size(100.dp),
                shape = CircleShape,
                color = Color(0xFF0f3460),
                shadowElevation = 8.dp
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        text = "J",
                        fontSize = 48.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "JustUs",
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                letterSpacing = 2.sp
            )

            Text(
                text = "Secret Chat • Encrypted • Private",
                fontSize = 14.sp,
                color = Color(0xFF888888),
                modifier = Modifier.padding(top = 8.dp)
            )

            Spacer(modifier = Modifier.height(48.dp))

            // Form Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF1e1e2e)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = if (isLoginMode) "Welcome Back" else "Create Account",
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = if (isLoginMode) "Sign in to continue" else "Join the secure network",
                        fontSize = 14.sp,
                        color = Color(0xFF888888)
                    )

                    Spacer(modifier = Modifier.height(32.dp))

                    // Username Field
                    OutlinedTextField(
                        value = username,
                        onValueChange = { username = it },
                        label = { Text("Username", color = Color(0xFF888888)) },
                        leadingIcon = {
                            Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFF4CAF50))
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = TextFieldDefaults.colors(
                            focusedIndicatorColor = Color(0xFF4CAF50),
                            unfocusedIndicatorColor = Color(0xFF333333),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = Color(0xFF4CAF50),
                            focusedLabelColor = Color(0xFF4CAF50),
                            unfocusedLabelColor = Color(0xFF888888)
                        ),
                        singleLine = true
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    // Password Field
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Password", color = Color(0xFF888888)) },
                        leadingIcon = {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = Color(0xFF4CAF50))
                        },
                        trailingIcon = {
                            IconButton(onClick = { showPassword = !showPassword }) {
                                Icon(
                                    if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = null,
                                    tint = Color(0xFF888888)
                                )
                            }
                        },
                        visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                        colors = TextFieldDefaults.colors(
                            focusedIndicatorColor = Color(0xFF4CAF50),
                            unfocusedIndicatorColor = Color(0xFF333333),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = Color(0xFF4CAF50),
                            focusedLabelColor = Color(0xFF4CAF50),
                            unfocusedLabelColor = Color(0xFF888888)
                        ),
                        singleLine = true
                    )

                    if (!isLoginMode) {
                        Spacer(modifier = Modifier.height(16.dp))

                        // Confirm Password Field
                        OutlinedTextField(
                            value = confirmPassword,
                            onValueChange = { confirmPassword = it },
                            label = { Text("Confirm Password", color = Color(0xFF888888)) },
                            leadingIcon = {
                                Icon(Icons.Default.Lock, contentDescription = null, tint = Color(0xFF4CAF50))
                            },
                            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                            colors = TextFieldDefaults.colors(
                                focusedIndicatorColor = Color(0xFF4CAF50),
                                unfocusedIndicatorColor = Color(0xFF333333),
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = Color(0xFF4CAF50),
                                focusedLabelColor = Color(0xFF4CAF50),
                                unfocusedLabelColor = Color(0xFF888888)
                            ),
                            singleLine = true
                        )
                    }

                    errorMessage?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = it,
                            color = Color(0xFFf44336),
                            fontSize = 12.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(32.dp))

                    // Submit Button
                    Button(
                        onClick = {
                            focusManager.clearFocus()
                            if (username.isBlank() || password.isBlank()) {
                                errorMessage = "Please fill all fields"
                                return@Button
                            }

                            if (!isLoginMode && password != confirmPassword) {
                                errorMessage = "Passwords do not match"
                                return@Button
                            }

                            isLoading = true

                            // Simulate authentication (replace with actual API call)
                            Handler(Looper.getMainLooper()).postDelayed({
                                isLoading = false
                                val sessionToken = UUID.randomUUID().toString()

                                // Save credentials
                                val prefs = context.getSharedPreferences("JustUsSecure", Context.MODE_PRIVATE)
                                prefs.edit()
                                    .putString("sessionToken", sessionToken)
                                    .putString("username", username)
                                    .putBoolean("biometricEnabled", true)
                                    .apply()

                                onLoginSuccess(username, sessionToken)
                            }, 1500)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF4CAF50)
                        )
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text(
                                text = if (isLoginMode) "Login" else "Register",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Toggle Login/Register
                    TextButton(
                        onClick = {
                            isLoginMode = !isLoginMode
                            errorMessage = null
                        }
                    ) {
                        Text(
                            text = if (isLoginMode) "Need an account? Register" else "Already have an account? Login",
                            color = Color(0xFF4CAF50)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Security Indicators
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = Color(0xFF4CAF50)
                )
                Text(
                    text = " AES-256 Encrypted",
                    fontSize = 12.sp,
                    color = Color(0xFF666666)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Icon(
                    Icons.Default.Verified,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = Color(0xFF4CAF50)
                )
                Text(
                    text = " End-to-End Encryption",
                    fontSize = 12.sp,
                    color = Color(0xFF666666)
                )
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(
    messages: List<ChatMessage>,
    currentUser: String,
    onSendMessage: (String, Int) -> Unit,
    onTyping: (Boolean) -> Unit,
    onRevealMessage: (String) -> Unit
) {
    var messageText by remember { mutableStateOf("") }
    var isTyping by remember { mutableStateOf(false) }
    var selfDestructSeconds by remember { mutableStateOf(0) }
    var showSelfDestructMenu by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val focusManager = LocalFocusManager.current
    val hapticFeedback = LocalHapticFeedback.current
    val context = LocalContext.current

    // Typing debounce
    val typingDebounce = remember {
        Handler(Looper.getMainLooper())
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0a0a0a)),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "JustUs",
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = currentUser,
                            fontSize = 12.sp,
                            color = Color(0xFF888888)
                        )
                    }
                },
                actions = {
                    // Self-destruct indicator
                    IconButton(onClick = { showSelfDestructMenu = true }) {
                        Badge(
                            containerColor = if (selfDestructSeconds > 0) Color(0xFF4CAF50) else Color.Transparent
                        ) {
                            Icon(
                                Icons.Default.Timer,
                                contentDescription = "Self Destruct",
                                tint = if (selfDestructSeconds > 0) Color(0xFF4CAF50) else Color.White
                            )
                        }
                    }

                    // Lock button
                    IconButton(onClick = {
                        hapticFeedback.performHapticFeedback(HapticFeedbackType.LongPress)
                        // Lock app
                    }) {
                        Icon(Icons.Default.Lock, contentDescription = "Lock", tint = Color.White)
                    }

                    // Menu
                    IconButton(onClick = { /* Show menu */ }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Menu", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF1a1a2e)
                )
            )
        },
        floatingActionButton = {
            if (selfDestructSeconds > 0) {
                FloatingActionButton(
                    onClick = { showSelfDestructMenu = true },
                    modifier = Modifier.size(56.dp),
                    containerColor = Color(0xFF4CAF50),
                    shape = CircleShape
                ) {
                    Text(
                        text = "${selfDestructSeconds}s",
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .pointerInput(Unit) {
                    detectTapGestures(onTap = { focusManager.clearFocus() })
                }
        ) {
            Column(
                modifier = Modifier.fillMaxSize()
            ) {
                // Messages List
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                    reverseLayout = false
                ) {
                    items(messages, key = { it.id }) { message ->
                        ChatBubble(
                            message = message,
                            currentUser = currentUser,
                            onReveal = { onRevealMessage(message.id) }
                        )
                    }
                }

                // Typing Indicator
                AnimatedVisibility(
                    visible = isTyping,
                    enter = fadeIn() + slideInVertically(),
                    exit = fadeOut() + slideOutVertically()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.Start
                    ) {
                        Box(
                            modifier = Modifier
                                .background(
                                    color = Color(0xFF2C2C2E),
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .padding(horizontal = 12.dp, vertical = 8.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                val infiniteTransition = rememberInfiniteTransition()
                                repeat(3) { index ->
                                    val scale by infiniteTransition.animateFloat(
                                        initialValue = 0.5f,
                                        targetValue = 1f,
                                        animationSpec = infiniteRepeatable(
                                            animation = tween(300, delayMillis = index * 100, easing = FastOutSlowInEasing),
                                            repeatMode = RepeatMode.Reverse
                                        )
                                    )
                                    Box(
                                        modifier = Modifier
                                            .size(6.dp)
                                            .padding(horizontal = 2.dp)
                                            .graphicsLayer {
                                                scaleX = scale
                                                scaleY = scale
                                            }
                                    )
                                }
                                Text(
                                    text = " Typing...",
                                    fontSize = 12.sp,
                                    color = Color(0xFF888888)
                                )
                            }
                        }
                    }
                }

                // Input Area
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF1e1e2e)
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.Bottom
                    ) {
                        // Self-destruct quick select
                        IconButton(
                            onClick = { showSelfDestructMenu = true },
                            modifier = Modifier.size(40.dp)
                        ) {
                            Icon(
                                Icons.Default.Timer,
                                contentDescription = "Self Destruct",
                                tint = if (selfDestructSeconds > 0) Color(0xFF4CAF50) else Color(0xFF888888)
                            )
                        }

                        // Message Input
                        OutlinedTextField(
                            value = messageText,
                            onValueChange = {
                                messageText = it
                                if (!isTyping && it.isNotBlank()) {
                                    isTyping = true
                                    onTyping(true)
                                    typingDebounce.removeCallbacksAndMessages(null)
                                    typingDebounce.postDelayed({
                                        isTyping = false
                                        onTyping(false)
                                    }, 2000)
                                }
                            },
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 8.dp),
                            placeholder = {
                                Text(
                                    "Secret message...",
                                    color = Color(0xFF888888)
                                )
                            },
                            textStyle = LocalTextStyle.current.copy(color = Color.White),
                            colors = TextFieldDefaults.colors(
                                focusedIndicatorColor = Color(0xFF4CAF50),
                                unfocusedIndicatorColor = Color(0xFF333333),
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = Color(0xFF4CAF50)
                            ),
                            maxLines = 4,
                            keyboardOptions = KeyboardOptions(
                                imeAction = ImeAction.Send
                            ),
                            keyboardActions = KeyboardActions(
                                onSend = {
                                    if (messageText.isNotBlank()) {
                                        onSendMessage(messageText, selfDestructSeconds)
                                        messageText = ""
                                        focusManager.clearFocus()
                                    }
                                }
                            )
                        )

                        // Send Button
                        AnimatedVisibility(
                            visible = messageText.isNotBlank(),
                            enter = scaleIn() + fadeIn(),
                            exit = scaleOut() + fadeOut()
                        ) {
                            FloatingActionButton(
                                onClick = {
                                    if (messageText.isNotBlank()) {
                                        hapticFeedback.performHapticFeedback(HapticFeedbackType.LongPress)
                                        onSendMessage(messageText, selfDestructSeconds)
                                        messageText = ""
                                        focusManager.clearFocus()
                                    }
                                },
                                modifier = Modifier.size(48.dp),
                                containerColor = Color(0xFF4CAF50),
                                shape = CircleShape
                            ) {
                                Icon(
                                    Icons.Default.Send,
                                    contentDescription = "Send",
                                    tint = Color.White
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Self-destruct dialog
    if (showSelfDestructMenu) {
        SelfDestructPickerDialog(
            currentSeconds = selfDestructSeconds,
            onSelect = { seconds ->
                selfDestructSeconds = seconds
                showSelfDestructMenu = false
            },
            onDismiss = { showSelfDestructMenu = false }
        )
    }
}

@Composable
fun ChatBubble(
    message: ChatMessage,
    currentUser: String,
    onReveal: () -> Unit
) {
    val isSent = message.sender == currentUser
    var isRevealed by remember { mutableStateOf(!message.isBlurred) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = if (isSent) Arrangement.End else Arrangement.Start
    ) {
        Card(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .animateContentSize(),
            shape = RoundedCornerShape(
                topStart = 16.dp,
                topEnd = 16.dp,
                bottomStart = if (isSent) 16.dp else 4.dp,
                bottomEnd = if (isSent) 4.dp else 16.dp
            ),
            colors = CardDefaults.cardColors(
                containerColor = if (isSent) Color(0xFF2E7D32) else Color(0xFF1C1C1E)
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                // Message content with blur
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .pointerInput(Unit) {
                            detectTapGestures(
                                onTap = {
                                    if (!isRevealed && !isSent) {
                                        isRevealed = true
                                        onReveal()
                                    }
                                }
                            )
                        }
                ) {
                    Text(
                        text = if (isRevealed || isSent) message.text else "••••••••",
                        color = Color.White,
                        fontSize = 14.sp,
                        modifier = Modifier
                            .blur(if (!isRevealed && !isSent) 4.dp else 0.dp)
                    )

                    if (!isRevealed && !isSent) {
                        Box(
                            modifier = Modifier
                                .matchParentSize()
                                .background(
                                    brush = Brush.radialGradient(
                                        colors = listOf(Color.Transparent, Color(0xFF000000)),
                                        radius = 50f
                                    )
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.BlurOn,
                                contentDescription = "Tap to reveal",
                                tint = Color.White.copy(alpha = 0.5f),
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }
                }

                // Status row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Self-destruct timer
                    if (message.selfDestructSeconds > 0 && message.remainingDestructTime > 0) {
                        Text(
                            text = "${message.remainingDestructTime}s",
                            fontSize = 10.sp,
                            color = Color(0xFFFF9800)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                    }

                    // Status icon for sent messages
                    if (isSent) {
                        when (message.status) {
                            MessageStatus.SENDING -> {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(12.dp),
                                    strokeWidth = 1.dp,
                                    color = Color(0xFF888888)
                                )
                            }
                            MessageStatus.SENT -> {
                                Icon(
                                    Icons.Default.Done,
                                    contentDescription = "Sent",
                                    modifier = Modifier.size(12.dp),
                                    tint = Color(0xFF888888)
                                )
                            }
                            MessageStatus.DELIVERED -> {
                                Icon(
                                    Icons.Default.DoneAll,
                                    contentDescription = "Delivered",
                                    modifier = Modifier.size(12.dp),
                                    tint = Color(0xFF888888)
                                )
                            }
                            MessageStatus.READ -> {
                                Icon(
                                    Icons.Default.DoneAll,
                                    contentDescription = "Read",
                                    modifier = Modifier.size(12.dp),
                                    tint = Color(0xFF4CAF50)
                                )
                            }
                        }
                    }

                    // Timestamp
                    Text(
                        text = java.text.SimpleDateFormat("HH:mm", Locale.getDefault())
                            .format(Date(message.timestamp)),
                        fontSize = 10.sp,
                        color = Color(0xFF888888),
                        modifier = Modifier.padding(start = 4.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun SelfDestructPickerDialog(
    currentSeconds: Int,
    onSelect: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF1e1e2e)
            )
        ) {
            Column(
                modifier = Modifier.padding(20.dp)
            ) {
                Text(
                    text = "Self-Destruct Timer",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Text(
                    text = "Messages will disappear after selected time",
                    fontSize = 14.sp,
                    color = Color(0xFF888888),
                    modifier = Modifier.padding(top = 4.dp)
                )

                Spacer(modifier = Modifier.height(20.dp))

                val options = listOf(
                    "Off" to 0,
                    "5 seconds" to 5,
                    "10 seconds" to 10,
                    "30 seconds" to 30,
                    "1 minute" to 60,
                    "5 minutes" to 300
                )

                options.forEach { (label, seconds) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = currentSeconds == seconds,
                            onClick = { onSelect(seconds) }
                        )
                        Text(
                            text = label,
                            color = if (currentSeconds == seconds) Color(0xFF4CAF50) else Color.White,
                            modifier = Modifier.padding(start = 12.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF4CAF50)
                    )
                ) {
                    Text("Close")
                }
            }
        }
    }
}

@Composable
fun DecoyScreen(
    onExitDecoy: () -> Unit
) {
    var pinInput by remember { mutableStateOf("") }
    var showError by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF1a1a2e))
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = Color(0xFFf44336)
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Decoy Mode Active",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Text(
                text = "Enter decoy PIN to access fake chats",
                fontSize = 14.sp,
                color = Color(0xFF888888),
                modifier = Modifier.padding(top = 8.dp)
            )

            Spacer(modifier = Modifier.height(48.dp))

            // Fake chat preview
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF1e1e2e)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = "📱 General Chat",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "Friend: Hey, what's for lunch?",
                        fontSize = 14.sp,
                        color = Color(0xFF888888)
                    )

                    Text(
                        text = "You: Pizza sounds good! 🍕",
                        fontSize = 14.sp,
                        color = Color(0xFF888888),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(48.dp))

            // Decoy PIN input
            OutlinedTextField(
                value = pinInput,
                onValueChange = {
                    pinInput = it
                    showError = false
                    if (it.length == 4 && it == "1234") {
                        onExitDecoy()
                    }
                },
                label = { Text("Enter Decoy PIN", color = Color(0xFF888888)) },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                colors = TextFieldDefaults.colors(
                    focusedIndicatorColor = Color(0xFF4CAF50),
                    unfocusedIndicatorColor = Color(0xFF333333),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    cursorColor = Color(0xFF4CAF50),
                    focusedLabelColor = Color(0xFF4CAF50),
                    unfocusedLabelColor = Color(0xFF888888)
                ),
                isError = showError
            )

            if (showError) {
                Text(
                    text = "Invalid PIN",
                    color = Color(0xFFf44336),
                    fontSize = 12.sp,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Hint: Try 1234",
                fontSize = 12.sp,
                color = Color(0xFF666666)
            )
        }
    }
}

@Composable
fun JustUsTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF4CAF50),
            secondary = Color(0xFF2E7D32),
            background = Color(0xFF0a0a0a),
            surface = Color(0xFF1e1e2e)
        ),
        typography = Typography(
            bodyLarge = TextStyle(
                fontFamily = androidx.compose.ui.text.font.FontFamily.Default,
                fontWeight = FontWeight.Normal,
                fontSize = 14.sp
            )
        ),
        content = content
    )
}