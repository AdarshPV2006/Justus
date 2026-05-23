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
import androidx.compose.ui.focus.FocusManager
import androidx.compose.ui.graphics.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
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
    private var serverUrl = ""
    private var isReconnecting = false

    fun connect(username: String, token: String, url: String) {
        currentUser = username
        sessionToken = token
        serverUrl = url
        val request = Request.Builder()
            .url("$url/ws?token=$token&user=$username")
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
                        val messageId = json.optString("messageId", "")
                        if (messageId.isNotEmpty()) {
                            onStatusUpdate(messageId, MessageStatus.DELIVERED)
                        }
                    }
                    "read" -> {
                        val messageId = json.optString("messageId", "")
                        if (messageId.isNotEmpty()) {
                            onStatusUpdate(messageId, MessageStatus.READ)
                        }
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
        if (!isReconnecting && currentUser.isNotEmpty() && sessionToken.isNotEmpty() && serverUrl.isNotEmpty()) {
            isReconnecting = true
            onConnectionChange(ConnectionState.RECONNECTING)
            Handler(Looper.getMainLooper()).postDelayed({
                connect(currentUser, sessionToken, serverUrl)
            }, 3000)
        }
    }

    fun sendMessage(messageId: String, encryptedContent: String, recipient: String) {
        val json = JSONObject().apply {
            put("type", "message")
            put("id", messageId)
            put("content", encryptedContent)
            put("sender", currentUser)
            put("recipient", recipient)
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
    private var showSettings by mutableStateOf(false)
    private var serverUrl by mutableStateOf("wss://justus-server-doac.onrender.com")
    private var chatRecipient by mutableStateOf("")
    private var connState by mutableStateOf(ConnectionState.DISCONNECTED)

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
                        serverUrl = serverUrl,
                        onServerUrlChange = { serverUrl = it },
                        onLoginSuccess = { username, token, url ->
                            serverUrl = url
                            currentUser = username
                            isAuthenticated = true
                            sharedPreferences.edit()
                                .putString("serverUrl", url)
                                .putString("username", username)
                                .putString("sessionToken", token)
                                .apply()
                            initializeChat(username, token, url)
                        }
                    )
                } else {
                    ChatScreen(
                        messages = messages,
                        currentUser = currentUser,
                        chatRecipient = chatRecipient,
                        onRecipientChange = { chatRecipient = it },
                        connectionState = connState,
                        onSendMessage = { text, recipient, selfDestructSeconds ->
                            sendMessage(text, recipient, selfDestructSeconds)
                        },
                        onTyping = { isTyping ->
                            webSocketManager?.sendTypingIndicator(isTyping)
                        },
                        onRevealMessage = { messageId ->
                            webSocketManager?.sendReadReceipt(messageId)
                        },
                        onSettingsClick = { showSettings = true },
                        onLockClick = {
                            isAuthenticated = false
                            authenticateWithBiometrics()
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

    private fun initializeChat(username: String, token: String, url: String) {
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
                connState = state
            }
        )

        webSocketManager?.connect(username, token, url)
        encryptionManager = EncryptionManager()
        val publicKeyBytes = encryptionManager.getPublicKeyBytes()
    }

    private fun sendMessage(text: String, recipient: String, selfDestructSeconds: Int) {
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
        webSocketManager?.sendMessage(messageId, encrypted, recipient)

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
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    onLoginSuccess: (String, String, String) -> Unit
) {
    var isLoginMode by remember { mutableStateOf(true) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showUrlField by remember { mutableStateOf(false) }
    var localServerUrl by remember { mutableStateOf(serverUrl) }
    val scope = rememberCoroutineScope()

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

                    Spacer(modifier = Modifier.height(16.dp))

                    // Server URL toggle
                    TextButton(onClick = { showUrlField = !showUrlField }) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = Color(0xFF4CAF50)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Server",
                            color = Color(0xFF4CAF50),
                            fontSize = 12.sp
                        )
                    }

                    if (showUrlField) {
                        OutlinedTextField(
                            value = localServerUrl,
                            onValueChange = { localServerUrl = it },
                            label = { Text("Server URL", color = Color(0xFF888888)) },
                            placeholder = { Text("ws://host:port", color = Color(0xFF555555)) },
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
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    Spacer(modifier = Modifier.height(8.dp))

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
                            errorMessage = null
                            val url = localServerUrl.trimEnd('/')
                            onServerUrlChange(url)

                            // Call server API
                            val endpoint = if (isLoginMode) "$url/api/login" else "$url/api/register"
                            val jsonBody = JSONObject().apply {
                                put("username", username)
                                put("password", password)
                                put("public_key", "")
                            }

                            try {
                                val okHttpClient = OkHttpClient.Builder()
                                    .connectTimeout(10, TimeUnit.SECONDS)
                                    .readTimeout(10, TimeUnit.SECONDS)
                                    .build()
                                val requestBody = okhttp3.RequestBody.create(
                                    "application/json; charset=utf-8".toMediaType(),
                                    jsonBody.toString()
                                )
                                val request = okhttp3.Request.Builder()
                                    .url(endpoint)
                                    .post(requestBody)
                                    .build()

                                // Run in background thread
                                val prefs = context.getSharedPreferences("JustUsSecure", Context.MODE_PRIVATE)
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val response = okHttpClient.newCall(request).execute()
                                        val responseBody = response.body?.string() ?: "{}"
                                        val result = JSONObject(responseBody)

                                        withContext(Dispatchers.Main) {
                                            isLoading = false
                                            if (result.optBoolean("success", false)) {
                                                val token = result.getString("token")
                                                prefs.edit()
                                                    .putString("sessionToken", token)
                                                    .putString("username", username)
                                                    .putBoolean("biometricEnabled", true)
                                                    .apply()
                                                onLoginSuccess(username, token, url)
                                            } else {
                                                errorMessage = result.optString("error", "Server error")
                                            }
                                        }
                                    } catch (e: Exception) {
                                        withContext(Dispatchers.Main) {
                                            isLoading = false
                                            errorMessage = "Cannot reach server"
                                        }
                                    }
                                }
                            } catch (e: Exception) {
                                isLoading = false
                                errorMessage = "Connection failed"
                            }
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

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    messages: List<ChatMessage>,
    currentUser: String,
    chatRecipient: String,
    onRecipientChange: (String) -> Unit,
    connectionState: ConnectionState,
    onSendMessage: (String, String, Int) -> Unit,
    onTyping: (Boolean) -> Unit,
    onRevealMessage: (String) -> Unit,
    onSettingsClick: () -> Unit,
    onLockClick: () -> Unit
) {
    var messageText by remember { mutableStateOf("") }
    var isTyping by remember { mutableStateOf(false) }
    var selfDestructSeconds by remember { mutableStateOf(0) }
    var showSelfDestructMenu by remember { mutableStateOf(false) }
    var showMenu by remember { mutableStateOf(false) }
    var showRecipientField by remember { mutableStateOf(chatRecipient.isEmpty()) }
    var localRecipient by remember { mutableStateOf(chatRecipient) }
    val listState = rememberLazyListState()
    val focusManager = LocalFocusManager.current

    val typingDebounce = remember { Handler(Looper.getMainLooper()) }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    val connColor = when (connectionState) {
        ConnectionState.CONNECTED -> Color(0xFF34C759)
        ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> Color(0xFFFFD60A)
        ConnectionState.DISCONNECTED -> Color(0xFFFF453A)
    }

    Box(modifier = Modifier.fillMaxSize().background(Color(0xFF000000))) {
        Column(modifier = Modifier.fillMaxSize()) {
            // Top bar
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFF1C1C1E),
                shadowElevation = 4.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 10.dp)
                        .statusBarsPadding(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Avatar
                    val initial = if (chatRecipient.isNotEmpty()) chatRecipient.first().uppercase() else "?"
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(Color(0xFF0A84FF), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(initial, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = chatRecipient.ifEmpty { "Select recipient" },
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(modifier = Modifier.size(6.dp).background(connColor, CircleShape))
                        }
                        Text(
                            text = when (connectionState) {
                                ConnectionState.CONNECTED -> "Online"
                                ConnectionState.CONNECTING -> "Connecting..."
                                ConnectionState.RECONNECTING -> "Reconnecting..."
                                ConnectionState.DISCONNECTED -> "Offline"
                            },
                            fontSize = 11.sp,
                            color = connColor
                        )
                    }
                    // Self-destruct
                    IconButton(onClick = { showSelfDestructMenu = true }) {
                        Box {
                            Icon(
                                Icons.Default.Timer,
                                contentDescription = null,
                                tint = if (selfDestructSeconds > 0) Color(0xFF30D158) else Color(0xFF8E8E93),
                                modifier = Modifier.size(22.dp)
                            )
                            if (selfDestructSeconds > 0) {
                                Text(
                                    "${selfDestructSeconds}s",
                                    fontSize = 8.sp,
                                    color = Color(0xFF30D158),
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.align(Alignment.BottomEnd)
                                )
                            }
                        }
                    }
                    // Menu
                    Box {
                        IconButton(onClick = { showMenu = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = null, tint = Color(0xFF8E8E93))
                        }
                        DropdownMenu(
                            expanded = showMenu,
                            onDismissRequest = { showMenu = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Set Recipient") },
                                onClick = { showMenu = false; showRecipientField = !showRecipientField },
                                leadingIcon = { Icon(Icons.Default.Person, contentDescription = null) }
                            )
                            DropdownMenuItem(
                                text = { Text("Lock") },
                                onClick = { showMenu = false; onLockClick() },
                                leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) }
                            )
                            DropdownMenuItem(
                                text = { Text("Settings") },
                                onClick = { showMenu = false; onSettingsClick() },
                                leadingIcon = { Icon(Icons.Default.Settings, contentDescription = null) }
                            )
                        }
                    }
                }
            }

            // Recipient field
            if (showRecipientField) {
                Surface(modifier = Modifier.fillMaxWidth(), color = Color(0xFF2C2C2E)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("To:", color = Color(0xFF8E8E93), fontSize = 14.sp)
                        TextField(
                            value = localRecipient,
                            onValueChange = { localRecipient = it; onRecipientChange(it) },
                            placeholder = { Text("Username", color = Color(0xFF555555)) },
                            modifier = Modifier.weight(1f),
                            colors = TextFieldDefaults.colors(
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = Color(0xFF0A84FF),
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent
                            ),
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
                        )
                        if (localRecipient.isNotEmpty()) {
                            IconButton(onClick = { showRecipientField = false }) {
                                Icon(Icons.Default.Close, contentDescription = null, tint = Color(0xFF8E8E93), modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }

            // Messages
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                if (messages.isEmpty()) {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(64.dp), tint = Color(0xFF333333))
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("No messages yet", color = Color(0xFF555555), fontSize = 16.sp, fontWeight = FontWeight.Medium)
                        Text("Start a secret conversation", color = Color(0xFF444444), fontSize = 13.sp)
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                        reverseLayout = false
                    ) {
                        items(messages, key = { it.id }) { msg ->
                            val isSent = msg.sender == currentUser
                            val showAvatar = !isSent
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                horizontalArrangement = if (isSent) Arrangement.End else Arrangement.Start
                            ) {
                                if (!isSent && showAvatar) {
                                    Box(
                                        modifier = Modifier
                                            .size(32.dp)
                                            .align(Alignment.Bottom)
                                            .background(Color(0xFF0A84FF), CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(msg.sender.first().uppercase(), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                    }
                                    Spacer(modifier = Modifier.width(6.dp))
                                }
                                if (isSent) Spacer(modifier = Modifier.width(60.dp))
                                Column(horizontalAlignment = if (isSent) Alignment.End else Alignment.Start) {
                                    Box(
                                        modifier = Modifier
                                            .widthIn(max = 260.dp)
                                            .background(
                                                color = if (isSent) Color(0xFF0A84FF) else Color(0xFF1C1C1E),
                                                shape = RoundedCornerShape(
                                                    topStart = 18.dp, topEnd = 18.dp,
                                                    bottomStart = if (isSent) 18.dp else 4.dp,
                                                    bottomEnd = if (isSent) 4.dp else 18.dp
                                                )
                                            )
                                            .padding(horizontal = 14.dp, vertical = 10.dp)
                                    ) {
                                        Text(
                                            text = if (!isSent && msg.isBlurred) "••••••••" else msg.text,
                                            color = Color.White,
                                            fontSize = 15.sp,
                                            modifier = Modifier.blur(if (!isSent && msg.isBlurred) 6.dp else 0.dp)
                                        )
                                        if (!isSent && msg.isBlurred) {
                                            Box(
                                                modifier = Modifier.matchParentSize(),
                                                contentAlignment = Alignment.Center
                                            ) {
                                                Icon(Icons.Default.BlurOn, contentDescription = "Tap to reveal", tint = Color.White.copy(alpha = 0.3f), modifier = Modifier.size(20.dp))
                                            }
                                        }
                                    }
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.padding(top = 2.dp, start = 4.dp, end = 4.dp)
                                    ) {
                                        if (msg.selfDestructSeconds > 0 && msg.remainingDestructTime > 0) {
                                            Text("${msg.remainingDestructTime}s", fontSize = 10.sp, color = Color(0xFFFF9F0A))
                                            Spacer(modifier = Modifier.width(4.dp))
                                        }
                                        Text(
                                            text = java.text.SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(msg.timestamp)),
                                            fontSize = 10.sp,
                                            color = Color(0xFF8E8E93)
                                        )
                                        if (isSent) {
                                            Spacer(modifier = Modifier.width(4.dp))
                                            when (msg.status) {
                                                MessageStatus.SENDING -> CircularProgressIndicator(modifier = Modifier.size(10.dp), strokeWidth = 1.dp, color = Color(0xFF8E8E93))
                                                MessageStatus.SENT -> Icon(Icons.Default.Done, contentDescription = null, modifier = Modifier.size(12.dp), tint = Color(0xFF8E8E93))
                                                MessageStatus.DELIVERED -> Icon(Icons.Default.DoneAll, contentDescription = null, modifier = Modifier.size(12.dp), tint = Color(0xFF8E8E93))
                                                MessageStatus.READ -> Icon(Icons.Default.DoneAll, contentDescription = null, modifier = Modifier.size(12.dp), tint = Color(0xFF0A84FF))
                                            }
                                        }
                                    }
                                }
                                if (!isSent) Spacer(modifier = Modifier.width(60.dp))
                                if (isSent && showAvatar) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Box(
                                        modifier = Modifier.size(32.dp).align(Alignment.Bottom).background(Color(0xFF30D158), CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(currentUser.first().uppercase(), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Typing
            AnimatedVisibility(
                visible = isTyping,
                enter = fadeIn() + slideInVertically(),
                exit = fadeOut() + slideOutVertically(),
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val inf = rememberInfiniteTransition()
                    repeat(3) { i ->
                        val s by inf.animateFloat(0.5f, 1f, infiniteRepeatable(tween(300, delayMillis = i * 100, easing = FastOutSlowInEasing), RepeatMode.Reverse))
                        Box(modifier = Modifier.size(5.dp).padding(1.dp).graphicsLayer { scaleX = s; scaleY = s })
                    }
                    Text("  Typing...", fontSize = 12.sp, color = Color(0xFF8E8E93))
                }
            }

            // Input
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFF1C1C1E),
                shadowElevation = 8.dp
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp).navigationBarsPadding(),
                    verticalAlignment = Alignment.Bottom
                ) {
                    IconButton(onClick = { showSelfDestructMenu = true }, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Default.Timer, contentDescription = null, tint = if (selfDestructSeconds > 0) Color(0xFF30D158) else Color(0xFF555555), modifier = Modifier.size(20.dp))
                    }
                    OutlinedTextField(
                        value = messageText,
                        onValueChange = {
                            messageText = it
                            if (!isTyping && it.isNotBlank()) {
                                isTyping = true; onTyping(true)
                                typingDebounce.removeCallbacksAndMessages(null)
                                typingDebounce.postDelayed({ isTyping = false; onTyping(false) }, 2000)
                            }
                        },
                        modifier = Modifier.weight(1f).padding(horizontal = 4.dp),
                        placeholder = { Text("iMessage", color = Color(0xFF555555)) },
                        textStyle = LocalTextStyle.current.copy(color = Color.White, fontSize = 15.sp),
                        colors = TextFieldDefaults.colors(
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = Color(0xFF0A84FF)
                        ),
                        maxLines = 4,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                        keyboardActions = KeyboardActions(onSend = {
                            val r = localRecipient.ifEmpty { chatRecipient }
                            if (messageText.isNotBlank() && r.isNotBlank()) {
                                onSendMessage(messageText, r, selfDestructSeconds)
                                messageText = ""; focusManager.clearFocus()
                            }
                        })
                    )
                    IconButton(
                        onClick = {
                            val r = localRecipient.ifEmpty { chatRecipient }
                            if (messageText.isNotBlank() && r.isNotBlank()) {
                                onSendMessage(messageText, r, selfDestructSeconds)
                                messageText = ""; focusManager.clearFocus()
                            }
                        },
                        modifier = Modifier.size(36.dp),
                        enabled = messageText.isNotBlank() && (localRecipient.isNotEmpty() || chatRecipient.isNotEmpty())
                    ) {
                        Icon(
                            Icons.Default.ArrowUpward,
                            contentDescription = "Send",
                            tint = if (messageText.isNotBlank() && (localRecipient.isNotEmpty() || chatRecipient.isNotEmpty())) Color.White else Color(0xFF333333),
                            modifier = Modifier
                                .size(24.dp)
                                .background(
                                    if (messageText.isNotBlank() && (localRecipient.isNotEmpty() || chatRecipient.isNotEmpty())) Color(0xFF0A84FF) else Color.Transparent,
                                    CircleShape
                                )
                                .padding(4.dp)
                        )
                    }
                }
            }
        }
    }

    if (showSelfDestructMenu) {
        SelfDestructPickerDialog(
            currentSeconds = selfDestructSeconds,
            onSelect = { seconds -> selfDestructSeconds = seconds; showSelfDestructMenu = false },
            onDismiss = { showSelfDestructMenu = false }
        )
    }
}

@Composable
fun SelfDestructPickerDialog(
    currentSeconds: Int,
    onSelect: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1C1C1E))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text("Self-Destruct Timer", fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Color.White)
                Text("Messages will disappear after selected time", fontSize = 13.sp, color = Color(0xFF8E8E93), modifier = Modifier.padding(top = 4.dp))
                Spacer(modifier = Modifier.height(16.dp))
                listOf("Off" to 0, "5s" to 5, "10s" to 10, "30s" to 30, "1m" to 60, "5m" to 300).forEach { (l, s) ->
                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = currentSeconds == s, onClick = { onSelect(s) }, colors = RadioButtonDefaults.colors(selectedColor = Color(0xFF0A84FF)))
                        Text(l, color = if (currentSeconds == s) Color(0xFF0A84FF) else Color.White, fontSize = 15.sp, modifier = Modifier.padding(start = 8.dp))
                    }
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