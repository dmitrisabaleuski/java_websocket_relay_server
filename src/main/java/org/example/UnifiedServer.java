package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.CharsetUtil;
import org.json.JSONObject;

import java.io.*;
import io.netty.channel.Channel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static io.netty.handler.codec.http.HttpHeaderNames.*;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.java_websocket.framing.TextWebSocketFrame;
import org.java_websocket.framing.BinaryWebSocketFrame;
import org.java_websocket.framing.CloseFrame;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

public class UnifiedServer extends WebSocketServer {

    private static final String SECRET = System.getenv().getOrDefault("JWT_SECRET", "eY9xh9F!j$3Kz0@VqLu7pT1cG2mNwqAr");
    private static final String UPLOADS_DIR = System.getenv().getOrDefault("UPLOADS_DIR", "uploads");

    private static final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private static final Map<String, Channel> clients = new ConcurrentHashMap<>();
    private static final Map<String, Long> fileTransferSize = new ConcurrentHashMap<>();
    private static final Map<String, Long> fileExpectedSize = new ConcurrentHashMap<>();
    private static final Map<String, OutputStream> activeFileStreams = new ConcurrentHashMap<>();
    private static final Map<String, String> activeFileNames = new ConcurrentHashMap<>();
    private final Map<String, ByteArrayOutputStream> fileBuffers = new ConcurrentHashMap<>();
    private static final int MAX_ACTIVE_TRANSFERS = 20;
    
    // PING/PONG heartbeat system
    private static final java.util.Timer heartbeatTimer = new java.util.Timer(true);
    private static final long HEARTBEAT_INTERVAL = 30000; // 30 seconds

    private static final Logger LOGGER = Logger.getLogger(UnifiedServer.class.getName());
    private static final int MAX_CLIENTS = 100;
    private static final int RATE_LIMIT_PER_MINUTE = 1000;
    private static final int HEARTBEAT_INTERVAL_WS = 30000; // 30 seconds
    
    // Client management
    private final Map<String, ClientInfo> clientsWS = new ConcurrentHashMap<>();
    private final Map<String, String> clientTokens = new ConcurrentHashMap<>();
    private final Map<String, String> pcClients = new ConcurrentHashMap<>();
    private final Map<String, String> androidClients = new ConcurrentHashMap<>();
    
    // Rate limiting
    private final Map<String, RateLimitInfo> rateLimits = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    
    // Caching
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final int MAX_CACHE_SIZE = 1000;
    private final long CACHE_TTL = 300000; // 5 minutes
    
    // Performance monitoring
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong totalBytesTransferred = new AtomicLong(0);
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final long startTime = System.currentTimeMillis();
    
    // Heartbeat
    private final ScheduledExecutorService heartbeatExecutor = Executors.newScheduledThreadPool(1);
    private final Timer heartbeatTimerWS = new Timer();
    
    // Load balancing
    private final LoadBalancer loadBalancer = new LoadBalancer();
    
    // Admin HTTP server
    private AdminHttpServer adminServer;
    
    public UnifiedServer(int port) {
        super(new InetSocketAddress(port));
        setupLogging();
        startHeartbeatTimer();
        startPerformanceMonitoring();
        startAdminServer(port + 1); // HTTP сервер на следующем порту
        LOGGER.info("HomeCloud Unified Server started on port " + port);
    }
    
    private void startAdminServer(int httpPort) {
        try {
            adminServer = new AdminHttpServer(httpPort);
            adminServer.start();
            LOGGER.info("Admin HTTP server started on port " + httpPort);
            LOGGER.info("Admin panel available at: http://localhost:" + httpPort + "/admin");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to start admin HTTP server", e);
        }
    }
    
    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("homecloud_server.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.ALL);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to setup file logging", e);
        }
    }
    
    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        String clientId = generateClientId();
        String clientAddress = conn.getRemoteSocketAddress().getAddress().getHostAddress();
        
        ClientInfo clientInfo = new ClientInfo(clientId, conn, clientAddress);
        clientsWS.put(clientId, clientInfo);
        activeConnections.incrementAndGet();
        
        // Rate limiting setup
        rateLimits.put(clientId, new RateLimitInfo());
        requestCounts.put(clientId, new AtomicInteger(0));
        
        LOGGER.info("Client connected: " + clientId + " from " + clientAddress);
        LOGGER.info("Active connections: " + activeConnections.get() + "/" + MAX_CLIENTS);
        
        // Send welcome message
        conn.send("WELCOME:" + clientId);
        
        // Check if we're at capacity
        if (activeConnections.get() >= MAX_CLIENTS) {
            LOGGER.warning("Server at maximum capacity, rejecting new connections");
            conn.close(CloseFrame.TRY_AGAIN_LATER, "Server at maximum capacity");
        }
    }
    
    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        String clientId = findClientId(conn);
        if (clientId != null) {
            clientsWS.remove(clientId);
            clientTokens.remove(clientId);
            pcClients.remove(clientId);
            androidClients.remove(clientId);
            rateLimits.remove(clientId);
            requestCounts.remove(clientId);
            activeConnections.decrementAndGet();
            
            LOGGER.info("Client disconnected: " + clientId + " (Code: " + code + ", Reason: " + reason + ")");
            LOGGER.info("Active connections: " + activeConnections.get());
        }
    }
    
    @Override
    public void onMessage(WebSocket conn, String message) {
        String clientId = findClientId(conn);
        if (clientId == null) {
            LOGGER.warning("Message from unknown client: " + message);
            return;
        }
        
        // Rate limiting check
        if (!checkRateLimit(clientId)) {
            LOGGER.warning("Rate limit exceeded for client: " + clientId);
            conn.send("ERROR:RATE_LIMIT_EXCEEDED");
            return;
        }
        
        // Update request count
        totalRequests.incrementAndGet();
        requestCounts.get(clientId).incrementAndGet();
        
        // Process message
        try {
            processMessage(clientId, conn, message);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error processing message from " + clientId + ": " + message, e);
            conn.send("ERROR:INTERNAL_ERROR");
        }
    }
    
    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        String clientId = findClientId(conn);
        if (clientId == null) return;
        
        // Update bytes transferred
        totalBytesTransferred.addAndGet(message.remaining());
        
        // Process binary message
        try {
            processBinaryMessage(clientId, conn, message);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error processing binary message from " + clientId, e);
        }
    }
    
    @Override
    public void onError(WebSocket conn, Exception ex) {
        String clientId = findClientId(conn);
        LOGGER.log(Level.SEVERE, "Error on connection " + clientId, ex);
    }
    
    @Override
    public void onStart() {
        LOGGER.info("HomeCloud Server started successfully");
        LOGGER.info("Maximum clients: " + MAX_CLIENTS);
        LOGGER.info("Rate limit: " + RATE_LIMIT_PER_MINUTE + " requests per minute");
        LOGGER.info("Admin panel available at: http://localhost:" + (getPort() + 1) + "/admin");
    }
    
    @Override
    public void onStop() {
        if (adminServer != null) {
            adminServer.stop();
        }
        LOGGER.info("HomeCloud Server stopped");
    }
    
    private void processMessage(String clientId, WebSocket conn, String message) {
        String[] parts = message.split(":", 2);
        String command = parts[0];
        String data = parts.length > 1 ? parts[1] : "";
        
        // Check cache first
        String cacheKey = clientId + ":" + message;
        CacheEntry cached = cache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            conn.send(cached.getResponse());
            return;
        }
        
        switch (command) {
            case "REGISTER_PAIR":
                handleRegisterPair(clientId, conn, data);
                break;
            case "PAIR_STATUS":
                handlePairStatus(clientId, conn, data);
                break;
            case "GET_FILES":
                handleGetFiles(clientId, conn);
                break;
            case "FILE_INFO":
                handleFileInfo(clientId, conn, data);
                break;
            case "FILE_DATA":
                handleFileData(clientId, conn, data);
                break;
            case "FILE_END":
                handleFileEnd(clientId, conn, data);
                break;
            case "FILE_RECEIVED":
                handleFileReceived(clientId, conn, data);
                break;
            case "DELETE_FILE":
                handleDeleteFile(clientId, conn, data);
                break;
            case "MISSING_FILES":
                handleMissingFiles(clientId, conn, data);
                break;
            case "PING":
                handlePing(clientId, conn);
                break;
            case "PONG":
                handlePong(clientId, conn);
                break;
            default:
                LOGGER.warning("Unknown command from " + clientId + ": " + command);
                conn.send("ERROR:UNKNOWN_COMMAND");
        }
        
        // Cache response if appropriate
        cacheResponse(cacheKey, "OK");
    }
    
    private void processBinaryMessage(String clientId, WebSocket conn, ByteBuffer message) {
        // Handle file data transfer
        LOGGER.info("Binary message received from " + clientId + ", size: " + message.remaining() + " bytes");
        
        // Forward to paired client if exists
        String pairedClientId = findPairedClient(clientId);
        if (pairedClientId != null) {
            WebSocket pairedConn = clientsWS.get(pairedClientId).getConnection();
            if (pairedConn != null && pairedConn.isOpen()) {
                pairedConn.send(message);
            }
        }
    }
    
    private boolean checkRateLimit(String clientId) {
        RateLimitInfo rateInfo = rateLimits.get(clientId);
        AtomicInteger count = requestCounts.get(clientId);
        
        long currentTime = System.currentTimeMillis();
        if (currentTime - rateInfo.getLastReset() > 60000) { // 1 minute
            rateInfo.setLastReset(currentTime);
            count.set(0);
        }
        
        return count.get() < RATE_LIMIT_PER_MINUTE;
    }
    
    private void cacheResponse(String key, String response) {
        if (cache.size() >= MAX_CACHE_SIZE) {
            // Remove oldest entries
            cache.entrySet().removeIf(entry -> entry.getValue().isExpired());
        }
        
        cache.put(key, new CacheEntry(response, System.currentTimeMillis() + CACHE_TTL));
    }
    
    private void startHeartbeatTimer() {
        heartbeatTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                sendHeartbeatToAllClients();
            }
        }, HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
    }
    
    private void startPerformanceMonitoring() {
        ScheduledExecutorService monitorExecutor = Executors.newScheduledThreadPool(1);
        monitorExecutor.scheduleAtFixedRate(() -> {
            logPerformanceMetrics();
        }, 60, 60, TimeUnit.SECONDS);
    }
    
    private void logPerformanceMetrics() {
        long uptime = System.currentTimeMillis() - startTime;
        LOGGER.info("=== Performance Metrics ===");
        LOGGER.info("Active connections: " + activeConnections.get());
        LOGGER.info("Total requests: " + totalRequests.get());
        LOGGER.info("Total bytes transferred: " + totalBytesTransferred.get());
        LOGGER.info("Cache size: " + cache.size());
        LOGGER.info("Uptime: " + (uptime / 1000 / 60) + " minutes");
        LOGGER.info("Memory usage: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024 + " MB");
    }
    
    // Getters for admin panel
    public long getActiveConnections() { return activeConnections.get(); }
    public long getTotalRequests() { return totalRequests.get(); }
    public long getTotalBytesTransferred() { return totalBytesTransferred.get(); }
    public long getUptime() { return System.currentTimeMillis() - startTime; }
    public Map<String, ClientInfo> getClients() { return new HashMap<>(clientsWS); }
    
    // Existing methods...
    private void handleRegisterPair(String clientId, WebSocket conn, String data) {
        String[] parts = data.split(":", 3);
        if (parts.length == 3) {
            String androidToken = parts[1];
            String pcToken = parts[2];
            String androidUserId = getUserIdFromToken(androidToken);
            String pcUserId = getUserIdFromToken(pcToken);
            if (androidUserId == null || pcUserId == null) {
                LOGGER.warning("Invalid JWT in REGISTER_PAIR. androidToken=" + androidToken + ", pcToken=" + pcToken);
                conn.send("ERROR:Invalid JWT token in REGISTER_PAIR");
                return;
            }
            tokenPairs.put(pcUserId, androidUserId);
            tokenPairs.put(androidUserId, pcUserId);

            Channel androidCh = clients.get(androidUserId);
            Channel pcCh = clients.get(pcUserId);
            LOGGER.info("IS TOKENS EXIST: ANDROID" + androidToken + " PC: " + pcToken + " PART: " + Arrays.toString(parts));
            if (androidCh != null) androidCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + pcUserId));
            if (pcCh != null) pcCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + androidUserId));
        } else {
            LOGGER.warning("Invalid REGISTER_PAIR format: " + data);
            conn.send("ERROR:Invalid REGISTER_PAIR format");
        }
    }
    
    private void handlePairStatus(String clientId, WebSocket conn, String data) {
        String pcToken = data.trim();
        String androidToken = tokenPairs.get(pcToken);
        if (androidToken != null) {
            LOGGER.info("Pair exists for pcToken=" + pcToken);
            conn.send("PAIR_STATUS:YES");
        } else {
            LOGGER.info("No pair for pcToken=" + pcToken);
            conn.send("PAIR_STATUS:NO");
        }
    }
    
    private void handleGetFiles(String clientId, WebSocket conn) {
        String targetToken = tokenPairs.get(clientId);
        if (targetToken == null) {
            LOGGER.warning("Target token not found for GET_FILES. clientId=" + clientId);
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for GET_FILES. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }
        target.writeAndFlush(new TextWebSocketFrame("GET_FILES"));
        LOGGER.info("Sent GET_FILES to target: " + targetToken);
    }
    
    private void handleFileInfo(String clientId, WebSocket conn, String data) {
        if (activeFileStreams.size() >= MAX_ACTIVE_TRANSFERS) {
            LOGGER.warning("BUSY:MAX_TRANSFERS for sender=" + clientId);
            conn.send("BUSY:MAX_TRANSFERS");
            return;
        }
        String[] parts = data.split(":", 6);
        LOGGER.info("FILE_INFO] parts: " + Arrays.toString(parts));
        LOGGER.info("FILE_INFO] parts.length: " + parts.length);
        if (parts.length >= 5) {
            String transferId = parts[1];
            String filename = parts[2];
            String size = parts[3];
            String previewUri = parts.length > 5 ? parts[5] : null;

            long expectedSize = Long.parseLong(size);

            fileTransferSize.put(transferId, 0L);
            fileExpectedSize.put(transferId, expectedSize);

            LOGGER.info("Start file transfer: transferId=" + transferId +
                    ", filename=" + filename + ", expectedSize=" + expectedSize + ", sender=" + clientId +
                    ", previewUri=" + previewUri);

            try {
                File uploadsDir = new File(UPLOADS_DIR);
                if (!uploadsDir.exists()) uploadsDir.mkdirs();
                OutputStream fos = new FileOutputStream(new File(uploadsDir, filename));
                activeFileStreams.put(transferId, fos);
                activeFileNames.put(transferId, filename);

                LOGGER.info("File stream opened for: " + filename);

            } catch (Exception e) {
                LOGGER.warning("Failed to open file stream: " + e.getMessage());
            }

            String targetToken = tokenPairs.get(clientId);
            if (targetToken == null) {
                LOGGER.warning("Target token not found for senderToken: " + clientId);
                conn.send("ERROR:Target not connected");
                return;
            }
            Channel target = clients.get(targetToken);
            if (target == null || !target.isActive()) {
                LOGGER.warning("Target channel not active for token: " + targetToken);
                conn.send("ERROR:Target client not connected");
                return;
            }

            target.writeAndFlush(new TextWebSocketFrame(data));
            conn.send("OK:READY:" + transferId);
        } else {
            LOGGER.warning("Invalid FILE_INFO format: " + data);
            conn.send("ERROR:Invalid FILE_INFO format");
        }
    }
    
    private void handleFileData(String clientId, WebSocket conn, String data) {
        String[] parts = data.split(":", 2);
        String transferId = parts[1];
        int dataLen = parts[0].length() - "FILE_DATA:".length(); // Calculate data length from prefix
        byte[] chunk = new byte[dataLen];
        System.arraycopy(data.getBytes(StandardCharsets.UTF_8), "FILE_DATA:".length(), chunk, 0, dataLen);

        OutputStream fos = activeFileStreams.get(transferId);
        LOGGER.info("FILE_DATA]: fos= " + fos);
        if (fos != null) {
            try {
                fos.write(chunk);
                long totalReceived = fileTransferSize.getOrDefault(transferId, 0L) + chunk.length;
                fileTransferSize.put(transferId, totalReceived);

                LOGGER.info("FILE_DATA: transferId=" + transferId +
                        ", chunkSize=" + chunk.length + ", totalReceived=" + totalReceived);

            } catch (IOException e) {
                LOGGER.warning("File write error: " + e.getMessage());
            }
        } else {
            LOGGER.warning("No file stream for transferId " + transferId);
        }

        String senderToken = clientId;
        String targetToken = tokenPairs.get(senderToken);
        if (targetToken == null) {
            LOGGER.warning("Target token not found for FILE_DATA. senderToken=" + senderToken);
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for FILE_DATA. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }
        if (target != null && target.isActive()) {
            ByteBuf toSend = Unpooled.buffer(data.length()); // Use original data length
            toSend.writeBytes(data.getBytes(StandardCharsets.UTF_8));
            target.writeAndFlush(new BinaryWebSocketFrame(toSend));

            LOGGER.info("Forwarded FILE_DATA chunk to target: " + targetToken +
                    ", transferId=" + transferId + ", chunkSize=" + chunk.length);

        }
    }
    
    private void handleFileEnd(String clientId, WebSocket conn, String data) {
        String[] parts = data.split(":", 2);
        String transferId = parts[1];

        OutputStream fos = activeFileStreams.remove(transferId);
        String fileName = activeFileNames.remove(transferId);
        if (fos != null) {
            try {
                fos.close();
                LOGGER.info("File saved: " + fileName + " (transferId=" + transferId + ")");
            } catch (Exception e) {
                LOGGER.warning("Error closing file: " + e.getMessage());
            }
        }
        fileTransferSize.remove(transferId);
        fileExpectedSize.remove(transferId);

        String targetToken = tokenPairs.get(clientId);
        if (targetToken == null) {
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for FILE_END. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }

        target.writeAndFlush(new TextWebSocketFrame("FILE_END:" + transferId));
        conn.send("FILE_RECEIVED:" + transferId);

        LOGGER.info("SLOT_FREE: " + transferId);

        conn.send("SLOT_FREE");
    }
    
    private void handleFileReceived(String clientId, WebSocket conn, String data) {
        String[] parts = data.split(":", 2);
        String transferId = parts[1];
        String targetToken = tokenPairs.get(clientId);
        if (targetToken == null) {
            LOGGER.warning("Target token not found for FILE_RECEIVED. senderToken=" + clientId);
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for FILE_RECEIVED. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }
        target.writeAndFlush(new TextWebSocketFrame("FILE_RECEIVED:" + transferId));
        LOGGER.info("FILE_RECEIVED relayed to target: " + targetToken + " transferId=" + transferId);
    }
    
    private void handleDeleteFile(String clientId, WebSocket conn, String data) {
        String fileId = data;
        String targetToken = tokenPairs.get(clientId);
        if (targetToken == null) {
            LOGGER.warning("Target token not found for DELETE_FILE. senderToken=" + clientId);
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for DELETE_FILE. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }

        target.writeAndFlush(new TextWebSocketFrame("DELETE_FILE:" + fileId));
        LOGGER.info("DELETE_FILE relayed to target: " + targetToken + " fileId=" + fileId);
    }
    
    private void handleMissingFiles(String clientId, WebSocket conn, String data) {
        String missingIdsJson = data;
        String targetToken = tokenPairs.get(clientId);
        if (targetToken == null) {
            LOGGER.warning("Target token not found for MISSING_FILES. senderToken=" + clientId);
            conn.send("ERROR:Target not connected");
            return;
        }
        Channel target = clients.get(targetToken);
        if (target == null || !target.isActive()) {
            LOGGER.warning("Target client not connected for MISSING_FILES. targetToken=" + targetToken);
            conn.send("ERROR:Target client not connected");
            return;
        }

        LOGGER.info("Forwarding missing file ids from sender: " + clientId + " to target: " + targetToken + " ids=" + missingIdsJson);

        target.writeAndFlush(new TextWebSocketFrame("REQUEST_PREVIEW:" + missingIdsJson));
    }
    
    private void handlePing(String clientId, WebSocket conn) {
        LOGGER.info("Received PING from userId=" + clientId);
        conn.send("PONG");
    }
    
    private void handlePong(String clientId, WebSocket conn) {
        // Update last heartbeat time
        ClientInfo clientInfo = clientsWS.get(clientId);
        if (clientInfo != null) {
            clientInfo.setLastHeartbeat(System.currentTimeMillis());
        }
    }
    
    private void sendHeartbeatToAllClients() {
        clientsWS.values().forEach(clientInfo -> {
            WebSocket conn = clientInfo.getConnection();
            if (conn != null && conn.isOpen()) {
                conn.send("PING");
            }
        });
    }
    
    private String generateClientId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
    
    private String findClientId(WebSocket conn) {
        return clientsWS.entrySet().stream()
                .filter(entry -> entry.getValue().getConnection() == conn)
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }
    
    private String findPairedClient(String clientId) {
        // Implementation for finding paired client
        return null;
    }
    
    // Inner classes for data structures
    public static class ClientInfo {
        private final String id;
        private final WebSocket connection;
        private final String address;
        private long lastHeartbeat;
        private int requestCount;
        
        public ClientInfo(String id, WebSocket connection, String address) {
            this.id = id;
            this.connection = connection;
            this.address = address;
            this.lastHeartbeat = System.currentTimeMillis();
            this.requestCount = 0;
        }
        
        // Getters and setters
        public String getId() { return id; }
        public WebSocket getConnection() { return connection; }
        public String getAddress() { return address; }
        public long getLastHeartbeat() { return lastHeartbeat; }
        public void setLastHeartbeat(long lastHeartbeat) { this.lastHeartbeat = lastHeartbeat; }
        public int getRequestCount() { return requestCount; }
        public void incrementRequestCount() { this.requestCount++; }
        public boolean isConnected() { return connection != null && connection.isOpen(); }
    }
    
    private static class RateLimitInfo {
        private long lastReset;
        
        public RateLimitInfo() {
            this.lastReset = System.currentTimeMillis();
        }
        
        public long getLastReset() { return lastReset; }
        public void setLastReset(long lastReset) { this.lastReset = lastReset; }
    }
    
    private static class CacheEntry {
        private final String response;
        private final long expirationTime;
        
        public CacheEntry(String response, long expirationTime) {
            this.response = response;
            this.expirationTime = expirationTime;
        }
        
        public String getResponse() { return response; }
        public boolean isExpired() { return System.currentTimeMillis() > expirationTime; }
    }
    
    private static class LoadBalancer {
        // Simple round-robin load balancing
        private final AtomicInteger counter = new AtomicInteger(0);
        
        public String getNextClient(Collection<String> clientIds) {
            if (clientIds.isEmpty()) return null;
            int index = counter.getAndIncrement() % clientIds.size();
            return clientIds.toArray(new String[0])[index];
        }
    }

    static class UnifiedServerHandler extends SimpleChannelInboundHandler<Object> {
        private WebSocketServerHandshaker handshaker;
        private String userId;

        @Override
        public void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (msg instanceof FullHttpRequest) {
                FullHttpRequest req = (FullHttpRequest) msg;
                if ("/api/token".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.POST) {
                    handleTokenRequest(ctx, req);
                } else if ("websocket".equalsIgnoreCase(req.headers().get("Upgrade"))) {
                    handleWebSocketHandshake(ctx, req);
                } else if ("/health".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
                } else {
                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND));
                }
            } else if (msg instanceof WebSocketFrame) {
                WebSocketFrame frame = (WebSocketFrame) msg;
                if (frame instanceof TextWebSocketFrame) {
                    String message = ((TextWebSocketFrame) frame).text();
                    if (userId == null) {
                        if (message.startsWith("AUTH:")) {
                            String jwt = message.substring("AUTH:".length());

                            System.out.println("[AUTH] Received AUTH for JWT: " + jwt);

                            userId = getUserIdFromToken(jwt);
                            if (userId == null) {
                                System.err.println("[AUTH] Invalid JWT, userId=null");
                                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT"));
                                ctx.close();
                                return;
                            }
                            clients.put(userId, ctx.channel());
                            ctx.channel().writeAndFlush(new TextWebSocketFrame("REGISTERED:" + userId));

                            System.out.println("[AUTH] Client registered: userId=" + userId + ", remote=" + ctx.channel().remoteAddress());

                            return;
                        } else {

                            System.err.println("[AUTH] Invalid JWT, userId=null");

                            ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT"));
                            ctx.close();
                            return;
                        }
                    }
                    handleTextMessage(ctx, message);
                    return;
                }
                if (frame instanceof BinaryWebSocketFrame) {
                    handleBinaryMessage(ctx, (BinaryWebSocketFrame) frame);
                } else if (frame instanceof CloseWebSocketFrame) {

                    System.out.println("[SERVER] Client requested close: userId=" + userId);

                    ctx.channel().close();
                }
            }
        }

        private void handleTokenRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                String body = req.content().toString(CharsetUtil.UTF_8);
                JSONObject json = new JSONObject(body);
                String userId = json.optString("userId");
                if (userId == null || userId.isEmpty()) {

                    System.err.println("[TOKEN] Unauthorized token request, userId missing");

                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED));
                    return;
                }
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                String token = JWT.create()
                        .withSubject(userId)
                        .withIssuedAt(new java.util.Date())
                        .sign(algorithm);
                ByteBuf content = Unpooled.copiedBuffer(token, CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "text/plain");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());

                System.out.println("[TOKEN] Issued JWT for userId=" + userId);

                sendHttpResponse(ctx, req, resp);
            } catch (Exception e) {

                System.err.println("[TOKEN] Failed to issue JWT: " + e.getMessage());

                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }

        private void handleWebSocketHandshake(ChannelHandlerContext ctx, FullHttpRequest req) {
            String wsUrl = "ws://" + req.headers().get(HOST) + req.uri();

            System.out.println("[WS] Handshake URI: " + wsUrl);

            WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory(wsUrl, null, true);
            handshaker = wsFactory.newHandshaker(req);

            // JWT check
            String authHeader = req.headers().get("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {

                System.err.println("[WS] Missing or invalid Authorization header");

                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Missing or invalid Authorization header"));
                ctx.close();
                return;
            }
            String jwtToken = authHeader.substring("Bearer ".length());
            try {
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                userId = JWT.require(algorithm).acceptLeeway(60).build().verify(jwtToken).getSubject();

                System.out.println("[WS] Authenticated userId=" + userId);

                clients.put(userId, ctx.channel());
                ctx.channel().writeAndFlush(new TextWebSocketFrame("REGISTERED:" + userId));
            } catch (Exception e) {

                System.err.println("[WS] Invalid JWT token: " + e.getMessage());

                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT token"));
                ctx.close();
                return;
            }

            if (handshaker != null) {
                handshaker.handshake(ctx.channel(), req);
            } else {

                System.err.println("[WS] WebSocket handshake failed");

                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:WebSocket handshake failed"));
                ctx.close();
            }
        }

        private void handleTextMessage(ChannelHandlerContext ctx, String message) {
            String senderToken = userId;

            if (userId == null) {

                System.err.println("[SERVER] ERROR: userId is null! message=" + message);

                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR: Not authenticated (userId null)"));
                return;
            }

            if (message.startsWith("FILE_INFO:")) {
                if (activeFileStreams.size() >= MAX_ACTIVE_TRANSFERS) {

                    System.err.println("[TRANSFER] BUSY:MAX_TRANSFERS for sender=" + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("BUSY:MAX_TRANSFERS"));
                    return;
                }
                String[] parts = message.split(":", 6);
                System.out.println("[FILE_INFO] parts: " + parts);
                System.out.println("[FILE_INFO] parts.length: " + parts.length);
                if (parts.length >= 5) {
                    String transferId = parts[1];
                    String filename = parts[2];
                    String size = parts[3];
                    String previewUri = parts.length > 5 ? parts[5] : null;

                    long expectedSize = Long.parseLong(size);

                    fileTransferSize.put(transferId, 0L);
                    fileExpectedSize.put(transferId, expectedSize);

                    System.out.println("[TRANSFER] Start file transfer: transferId=" + transferId +
                            ", filename=" + filename + ", expectedSize=" + expectedSize + ", sender=" + senderToken +
                            ", previewUri=" + previewUri);

                    try {
                        File uploadsDir = new File(UPLOADS_DIR);
                        if (!uploadsDir.exists()) uploadsDir.mkdirs();
                        OutputStream fos = new FileOutputStream(new File(uploadsDir, filename));
                        activeFileStreams.put(transferId, fos);
                        activeFileNames.put(transferId, filename);

                        System.out.println("[TRANSFER] File stream opened for: " + filename);

                    } catch (Exception e) {

                        System.err.println("[TRANSFER] Failed to open file stream: " + e.getMessage());

                    }

                    String targetToken = tokenPairs.get(senderToken);
                    if (targetToken == null) {
                        System.err.println("[SERVER] Target token not found for senderToken: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                        return;
                    }
                    Channel target = clients.get(targetToken);
                    if (target == null || !target.isActive()) {

                        System.err.println("[TRANSFER] Target channel not active for token: " + targetToken);

                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                        return;
                    }

                    target.writeAndFlush(new TextWebSocketFrame(message));
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("OK:READY:" + transferId));
                } else {

                    System.err.println("[TRANSFER] Invalid FILE_INFO format: " + message);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid FILE_INFO format"));
                }

            } else if (message.startsWith("REGISTER_PAIR:")) {
                String[] parts = message.split(":", 3);
                if (parts.length == 3) {
                    String androidToken = parts[1];
                    String pcToken = parts[2];
                    String androidUserId = getUserIdFromToken(androidToken);
                    String pcUserId = getUserIdFromToken(pcToken);
                    if (androidUserId == null || pcUserId == null) {

                        System.err.println("[PAIR] Invalid JWT in REGISTER_PAIR. androidToken=" + androidToken + ", pcToken=" + pcToken);

                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT token in REGISTER_PAIR"));
                        return;
                    }
                    tokenPairs.put(pcUserId, androidUserId);
                    tokenPairs.put(androidUserId, pcUserId);

                    Channel androidCh = clients.get(androidUserId);
                    Channel pcCh = clients.get(pcUserId);
                    System.err.println("IS TOKENS EXIST: ANDROID" + androidToken + " PC: " + pcToken + " PART: " + parts);
                    if (androidCh != null) androidCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + pcUserId));
                    if (pcCh != null) pcCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + androidUserId));
                } else {

                    System.err.println("[PAIR] Invalid REGISTER_PAIR format: " + message);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid REGISTER_PAIR format"));
                }
            } else if (message.startsWith("FILE_END:")) {
                String[] parts = message.split(":", 2);
                String transferId = parts[1];

                OutputStream fos = activeFileStreams.remove(transferId);
                String fileName = activeFileNames.remove(transferId);
                if (fos != null) {
                    try {
                        fos.close();

                        System.out.println("[TRANSFER] File saved: " + fileName + " (transferId=" + transferId + ")");

                    } catch (Exception e) {

                        System.err.println("[TRANSFER] Error closing file: " + e.getMessage());

                    }
                }
                fileTransferSize.remove(transferId);
                fileExpectedSize.remove(transferId);

                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[TRANSFER] Target client not connected for FILE_END. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                target.writeAndFlush(new TextWebSocketFrame("FILE_END:" + transferId));
                ctx.channel().writeAndFlush(new TextWebSocketFrame("FILE_RECEIVED:" + transferId));

                System.out.println("[TRANSFER] SLOT_FREE: " + transferId);

                ctx.channel().writeAndFlush(new TextWebSocketFrame("SLOT_FREE"));
            } else if (message.equals("DELETE_PAIRING")) {
                String pairToken = tokenPairs.remove(senderToken);
                if (pairToken != null) {
                    tokenPairs.remove(pairToken);
                    Channel pairCh = clients.get(pairToken);
                    if (pairCh != null) {
                        pairCh.writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:" + senderToken));
                        pairCh.writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
                    }
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:SUCCESS"));

                    System.out.println("[PAIR] Pairing deleted for sender: " + senderToken + " and pair: " + pairToken);

                } else {

                    System.err.println("[PAIR] No pairing found for sender: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:No pairing found"));
                }
            } else if (message.startsWith("FILE_RECEIVED:")) {
                String[] parts = message.split(":", 2);
                String transferId = parts[1];
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[TRANSFER] Target token not found for FILE_RECEIVED. senderToken=" + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[TRANSFER] Target client not connected for FILE_RECEIVED. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }
                target.writeAndFlush(new TextWebSocketFrame("FILE_RECEIVED:" + transferId));

                System.out.println("[TRANSFER] FILE_RECEIVED relayed to target: " + targetToken + " transferId=" + transferId);

            } else if (message.startsWith("FILE_LIST:")) {
                String fileListJson = message.substring("FILE_LIST:".length());
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[FILE_LIST] Target token not found for senderToken: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[FILE_LIST] Target client not connected for FILE_LIST. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }
                target.writeAndFlush(new TextWebSocketFrame("FILE_LIST:" + fileListJson));

                System.out.println("[FILE_LIST] Relayed file list to target: " + targetToken);

            } else if (message.startsWith("DELETE_FILE:")) {
                String fileId = message.substring("DELETE_FILE:".length());
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[DELETE_FILE] Target token not found for senderToken: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[DELETE_FILE] Target client not connected for DELETE_FILE. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                target.writeAndFlush(new TextWebSocketFrame("DELETE_FILE:" + fileId));

                System.out.println("[DELETE_FILE] DELETE_FILE relayed to target: " + targetToken + " fileId=" + fileId);

            } else if (message.equals("GET_FILES")) {
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[GET_FILES] Target token not found for senderToken: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[GET_FILES] Target client not connected for GET_FILES. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }
                target.writeAndFlush(new TextWebSocketFrame("GET_FILES"));

                System.out.println("[GET_FILES] Sent GET_FILES to target: " + targetToken);

            } else if (message.startsWith("MISSING_FILES:")) {
                String missingIdsJson = message.substring("MISSING_FILES:".length());
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[MISSING_FILES] Target token not found for senderToken: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[MISSING_FILES] Target client not connected for MISSING_FILES. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                System.out.println("[MISSING_FILES] Forwarding missing file ids from sender: " + senderToken + " to target: " + targetToken + " ids=" + missingIdsJson);

                target.writeAndFlush(new TextWebSocketFrame("REQUEST_PREVIEW:" + missingIdsJson));
            } else if (message.startsWith("PREVIEW_UPDATED:")) {
                String previewsJson = message.substring("PREVIEW_UPDATED:".length());
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[PREVIEW_UPDATED] Target token not found for senderToken: " + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[PREVIEW_UPDATED] Target client not connected for PREVIEW_UPDATED. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                System.out.println("[PREVIEW_UPDATED] Forwarded previews to target: " + targetToken);

                target.writeAndFlush(new TextWebSocketFrame("PREVIEW_UPDATED:" + previewsJson));
            } else if (message.startsWith("REQUEST_FILE:")) {
                String fileName = message.substring("REQUEST_FILE:".length()).trim();

                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {
                    System.err.println("[REQUEST_FILE] Target token not found for senderToken: " + senderToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }

                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {
                    System.err.println("[REQUEST_FILE] Target client not connected for REQUEST_FILE. targetToken=" + targetToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                System.out.println("[REQUEST_FILE] Forwarded REQUEST_FILE for file: " + fileName + " to target: " + targetToken);

                target.writeAndFlush(new TextWebSocketFrame("REQUEST_FILE:" + fileName));

            } else if (message.equals("PING")) {
                System.out.println("[PING] Received PING from userId=" + senderToken);
                ctx.channel().writeAndFlush(new TextWebSocketFrame("PONG"));
            } else if (message.equals("PONG")) {
                System.out.println("[PONG] Received PONG from userId=" + senderToken);
            } else if (message.startsWith("IS_PAIRED:")) {
                String pcToken = message.substring("IS_PAIRED:".length()).trim();
                String androidToken = tokenPairs.get(pcToken);
                if (androidToken != null) {

                    System.out.println("[PAIR] Pair exists for pcToken=" + pcToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:YES"));
                } else {

                    System.out.println("[PAIR] No pair for pcToken=" + pcToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
                }
            } else {

                System.err.println("[SERVER] ERROR: Unknown command from userId=" + senderToken + " message=" + message);

                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Unknown command"));
            }
        }

        private void handleBinaryMessage(ChannelHandlerContext ctx, BinaryWebSocketFrame frame) {
            System.out.println("[SERVER] BinaryWebSocketFrame received. Total size: " + frame.content().readableBytes());
            ByteBuf buffer = frame.content();
            buffer = buffer.retainedDuplicate();
            byte[] prefixBytes = new byte[64];
            buffer.readBytes(prefixBytes);
            String prefix = new String(prefixBytes, StandardCharsets.UTF_8).trim();

            if (prefix.startsWith("FILE_DATA:")) {
                String transferId = prefix.substring("FILE_DATA:".length()).trim();
                System.out.println("[FILE_DATA]: transferId= " + transferId);
                int dataLen = buffer.readableBytes();
                byte[] chunk = new byte[dataLen];
                buffer.readBytes(chunk);

                OutputStream fos = activeFileStreams.get(transferId);
                System.out.println("[FILE_DATA]: fos= " + fos);
                if (fos != null) {
                    try {
                        fos.write(chunk);
                        long totalReceived = fileTransferSize.getOrDefault(transferId, 0L) + chunk.length;
                        fileTransferSize.put(transferId, totalReceived);

                        System.out.println("[TRANSFER] FILE_DATA: transferId=" + transferId +
                                ", chunkSize=" + chunk.length + ", totalReceived=" + totalReceived);

                    } catch (IOException e) {

                        System.err.println("[TRANSFER] File write error: " + e.getMessage());

                    }
                } else {

                    System.err.println("[TRANSFER] No file stream for transferId " + transferId);

                }

                String senderToken = userId;
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {

                    System.err.println("[TRANSFER] Target token not found for FILE_DATA. senderToken=" + senderToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {

                    System.err.println("[TRANSFER] Target client not connected for FILE_DATA. targetToken=" + targetToken);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }
                if (target != null && target.isActive()) {
                    ByteBuf toSend = Unpooled.buffer(prefixBytes.length + chunk.length);
                    toSend.writeBytes(prefixBytes);
                    toSend.writeBytes(chunk);
                    target.writeAndFlush(new BinaryWebSocketFrame(toSend));

                    System.out.println("[TRANSFER] Forwarded FILE_DATA chunk to target: " + targetToken +
                            ", transferId=" + transferId + ", chunkSize=" + chunk.length);

                }
            } else {

                System.err.println("[SERVER] Unknown binary prefix received: " + prefix);

            }
            buffer.release();
        }

        private String getUserIdFromToken(String jwtToken) {
            try {
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                return JWT.require(algorithm).acceptLeeway(60).build().verify(jwtToken).getSubject();
            } catch (Exception e) {

                System.err.println("[JWT] Error decoding token: " + e.getMessage());

                return null;
            }
        }

        private void sendHttpResponse(ChannelHandlerContext ctx, FullHttpRequest req, FullHttpResponse res) {
            ChannelFuture f = ctx.channel().writeAndFlush(res);
            if (!HttpUtil.isKeepAlive(req) || res.status().code() != 200) {
                f.addListener(ChannelFutureListener.CLOSE);
            }
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) {
            String toRemove = null;
            for (Map.Entry<String, Channel> entry : clients.entrySet()) {
                if (entry.getValue().id().equals(ctx.channel().id())) {
                    toRemove = entry.getKey();
                    break;
                }
            }
            if (toRemove != null) {
                clients.remove(toRemove);

                System.out.println("[SERVER] Client disconnected: userId=" + toRemove);

            }else {

                System.out.println("[SERVER] handlerRemoved: couldn't find channel " + ctx.channel().id());

            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {

            System.err.println("[EXCEPTION] " + cause.getMessage());

            cause.printStackTrace();
            ctx.close();
        }
    }
}