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
import org.example.admin.AdminWebInterface;
import org.example.admin.PairManager;

import java.io.*;
import io.netty.channel.Channel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static io.netty.handler.codec.http.HttpHeaderNames.*;

public class UnifiedServer {

    // ⚠️ SECURITY WARNING: JWT_SECRET MUST be set as environment variable!
    // The default value is ONLY for development/testing.
    // For production: 
    // 1. Generate a strong random secret (32+ characters)
    // 2. Set JWT_SECRET environment variable
    // 3. NEVER commit the real secret to version control!
    private static final String SECRET = System.getenv().getOrDefault("JWT_SECRET", "eY9xh9F!j$3Kz0@VqLu7pT1cG2mNwqAr");
    private static final String UPLOADS_DIR = System.getenv().getOrDefault("UPLOADS_DIR", "uploads");

    private static final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private static final Map<String, Channel> clients = new ConcurrentHashMap<>();
    private static final Map<String, Channel> pendingPairChecks = new ConcurrentHashMap<>();
    private static final Map<String, Long> fileTransferSize = new ConcurrentHashMap<>();
    private static final Map<String, Long> fileExpectedSize = new ConcurrentHashMap<>();
    private static final Map<String, OutputStream> activeFileStreams = new ConcurrentHashMap<>();
    private static final Map<String, String> activeFileNames = new ConcurrentHashMap<>();
    private static final Map<String, String> transferOwners = new ConcurrentHashMap<>(); // transferId -> userId (who initiated transfer)
    private final Map<String, ByteArrayOutputStream> fileBuffers = new ConcurrentHashMap<>();
    
    // Transfer limits
    private static final int MAX_ACTIVE_TRANSFERS = 20; // Global limit
    private static final int MAX_TRANSFERS_PER_USER = 5; // Per-user limit for better fairness
    private static final long MAX_FILE_SIZE = 500L * 1024L * 1024L; // 500 MB maximum file size
    
    // PING/PONG heartbeat system
    private static final java.util.Timer heartbeatTimer = new java.util.Timer(true);
    private static final long HEARTBEAT_INTERVAL = 30000; // 30 seconds

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        File uploads = new File(UPLOADS_DIR);
        if (!uploads.exists()) uploads.mkdirs();
        
        // Load pairings on startup
        UnifiedServerHandler.loadPairings();

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            pipeline.addLast(new HttpServerCodec());
                            pipeline.addLast(new HttpObjectAggregator(64 * 1024 * 1024));
                            pipeline.addLast(new WebSocketServerProtocolHandler("/", null, true, 64 * 1024 * 1024));
                            pipeline.addLast(new WebSocketFrameAggregator(64 * 1024 * 1024));
                            pipeline.addLast(new ChunkedWriteHandler());
                            pipeline.addLast(new UnifiedServerHandler());
                        }
                    });

            AdminLogger.info("SERVER", "Netty server started on port " + port);
            
            // Start heartbeat timer
            startHeartbeatTimer();
            AdminLogger.info("SERVER", "Heartbeat timer started with interval: " + HEARTBEAT_INTERVAL + "ms");

            b.bind(port).sync().channel().closeFuture().sync();
        } finally {
            stopHeartbeatTimer();
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
    
    /**
     * Start heartbeat timer to send PING to all connected clients
     */
    private static void startHeartbeatTimer() {
        heartbeatTimer.scheduleAtFixedRate(new java.util.TimerTask() {
            @Override
            public void run() {
                try {
                    sendHeartbeatToAllClients();
                } catch (Exception e) {
                    System.err.println("[HEARTBEAT] Error sending heartbeat: " + e.getMessage());
                }
            }
        }, HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
    }
    
    /**
     * Stop heartbeat timer
     */
    private static void stopHeartbeatTimer() {
        if (heartbeatTimer != null) {
            heartbeatTimer.cancel();
            System.out.println("[HEARTBEAT] Heartbeat timer stopped");
        }
    }
    
    /**
     * Send PING to all connected clients and cleanup stale data
     */
    private static void sendHeartbeatToAllClients() {
        if (clients.isEmpty()) {
            return;
        }
        
        System.out.println("[HEARTBEAT] Sending PING to " + clients.size() + " connected clients");
        
        for (Map.Entry<String, Channel> entry : clients.entrySet()) {
            Channel channel = entry.getValue();
            String userId = entry.getKey();
            
            if (channel != null && channel.isActive()) {
                try {
                    channel.writeAndFlush(new TextWebSocketFrame("PING"));
                    System.out.println("[HEARTBEAT] Sent PING to userId: " + userId);
                } catch (Exception e) {
                    System.err.println("[HEARTBEAT] Failed to send PING to userId " + userId + ": " + e.getMessage());
                    // Remove inactive channel
                    clients.remove(userId);
                    System.out.println("[HEARTBEAT] Removed inactive channel for userId: " + userId);
                }
            } else {
                // Remove inactive channel
                clients.remove(userId);
                System.out.println("[HEARTBEAT] Removed inactive channel for userId: " + userId);
            }
        }
        
        // MEMORY LEAK FIX: Cleanup stale pending pair checks
        int cleaned = 0;
        java.util.Iterator<Map.Entry<String, Channel>> iterator = pendingPairChecks.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Channel> entry = iterator.next();
            Channel channel = entry.getValue();
            
            // Remove if channel is no longer active
            if (channel == null || !channel.isActive()) {
                iterator.remove();
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            System.out.println("[HEARTBEAT] Cleaned " + cleaned + " stale pending pair checks");
        }
    }

    static class UnifiedServerHandler extends SimpleChannelInboundHandler<Object> {
        private WebSocketServerHandshaker handshaker;
        private String userId;
        private static boolean pairingsLoaded = false;
        private AdminWebInterface adminInterface;

        public UnifiedServerHandler() {
            this.adminInterface = new AdminWebInterface(tokenPairs, clients, UnifiedServerHandler::savePairings);
        }

        @Override
        public void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
            // Load pairings on first connection if not already loaded
            if (!pairingsLoaded) {
                synchronized (UnifiedServerHandler.class) {
                    if (!pairingsLoaded) {
                        loadPairings();
                        pairingsLoaded = true;
                    }
                }
            }
            
            if (msg instanceof FullHttpRequest) {
                FullHttpRequest req = (FullHttpRequest) msg;
                
                // Admin interface routes (check first)
                if (req.uri().startsWith("/admin")) {
                    if (adminInterface.handleAdminRequest(ctx, req)) {
                        return; // Request handled by admin interface
                    }
                }
                
                if ("/api/token".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.POST) {
                    handleTokenRequest(ctx, req);
                } else if ("websocket".equalsIgnoreCase(req.headers().get("Upgrade"))) {
                    handleWebSocketHandshake(ctx, req);
                } else if ("/health".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleHealthCheck(ctx, req);
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

                            userId = getUserIdFromToken(jwt);
                            if (userId == null) {
                                AdminLogger.warn("AUTH", "Invalid or expired JWT from: " + ctx.channel().remoteAddress());
                                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:TOKEN_EXPIRED"));
                                ctx.close();
                                return;
                            }
                            clients.put(userId, ctx.channel());
                            ctx.channel().writeAndFlush(new TextWebSocketFrame("REGISTERED:" + userId));

                            AdminLogger.info("AUTH", "Client registered: userId=" + userId + ", address=" + ctx.channel().remoteAddress());

                            return;
                        } else {
                            AdminLogger.warn("AUTH", "Authentication failed - no AUTH message from: " + ctx.channel().remoteAddress());
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
                
                // SECURITY: Validate userId
                if (userId == null || userId.isEmpty()) {
                    AdminLogger.security("TOKEN", "Unauthorized token request - userId missing from: " + ctx.channel().remoteAddress());
                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED));
                    return;
                }
                
                if (userId.length() > 100) {
                    AdminLogger.security("TOKEN", "userId too long (" + userId.length() + " chars) from: " + ctx.channel().remoteAddress());
                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST));
                    return;
                }
                
                if (!userId.matches("^[a-zA-Z0-9_-]+$")) {
                    AdminLogger.security("TOKEN", "userId contains invalid characters: " + userId + " from: " + ctx.channel().remoteAddress());
                    sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST));
                    return;
                }
                
                // Get expiration hours from request (default: 7 days = 168 hours)
                long expirationHours = json.optLong("expirationHours", 168L);
                
                // SECURITY: Validate expiration (minimum 1 hour, maximum 30 days)
                if (expirationHours < 1) expirationHours = 1L;
                if (expirationHours > 720) expirationHours = 720L; // Max 30 days (more secure than 1 year)
                
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                
                java.util.Date now = new java.util.Date();
                java.util.Date expiresAt = new java.util.Date(now.getTime() + (expirationHours * 60 * 60 * 1000));
                
                String token = JWT.create()
                        .withSubject(userId)
                        .withIssuedAt(now)
                        .withExpiresAt(expiresAt)
                        .sign(algorithm);
                
                AdminLogger.info("TOKEN", "Issued JWT for userId=" + userId + ", expires in " + expirationHours + " hours (" + (expirationHours / 24) + " days)");
                ByteBuf content = Unpooled.copiedBuffer(token, CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "text/plain");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());

                sendHttpResponse(ctx, req, resp);
            } catch (IllegalArgumentException e) {
                AdminLogger.error("TOKEN", "Invalid request parameters: " + e.getMessage());
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST));
            } catch (Exception e) {
                AdminLogger.error("TOKEN", "Server error issuing JWT: " + e.getMessage());
                e.printStackTrace();
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }

        private void handleHealthCheck(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                JSONObject health = new JSONObject();
                health.put("status", "UP");
                health.put("connectedClients", clients.size());
                health.put("activePairings", tokenPairs.size() / 2); // Divide by 2 because each pair is stored twice
                health.put("activeTransfers", activeFileStreams.size());
                health.put("maxTransfers", MAX_ACTIVE_TRANSFERS);
                health.put("maxTransfersPerUser", MAX_TRANSFERS_PER_USER);
                health.put("maxFileSizeMB", MAX_FILE_SIZE / 1024 / 1024);
                health.put("uptime", ServerStatistics.getUptime());
                
                ByteBuf content = Unpooled.copiedBuffer(health.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "application/json");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
            } catch (Exception e) {
                AdminLogger.error("HEALTH", "Error generating health check: " + e.getMessage());
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
                // Count active transfers for this user
                long userActiveTransfers = transferOwners.values().stream()
                    .filter(owner -> owner.equals(senderToken))
                    .count();
                
                // Check global limit
                if (activeFileStreams.size() >= MAX_ACTIVE_TRANSFERS) {
                    System.err.println("[TRANSFER] ❌ BUSY:MAX_TRANSFERS (global limit) for sender=" + senderToken);
                    System.err.println("[TRANSFER] Active transfers list:");
                    for (Map.Entry<String, String> entry : transferOwners.entrySet()) {
                        System.err.println("  - transferId=" + entry.getKey() + ", owner=" + entry.getValue() + 
                                         ", fileName=" + activeFileNames.get(entry.getKey()));
                    }

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("BUSY:MAX_TRANSFERS"));
                    return;
                }
                
                // Check per-user limit for fairness
                if (userActiveTransfers >= MAX_TRANSFERS_PER_USER) {
                    System.err.println("[TRANSFER] ❌ BUSY:MAX_TRANSFERS (per-user limit " + MAX_TRANSFERS_PER_USER + ") for sender=" + senderToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("BUSY:MAX_TRANSFERS"));
                    return;
                }
                String[] parts = message.split(":", 6);
                if (parts.length >= 5) {
                    String transferId = parts[1];
                    String filename = parts[2];
                    String size = parts[3];
                    String previewUri = parts.length > 5 ? parts[5] : null;

                    // SECURITY: Validate filename to prevent path traversal attacks
                    if (filename == null || filename.isEmpty()) {
                        AdminLogger.security("VALIDATION", "Empty filename rejected from user: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid filename"));
                        return;
                    }
                    
                    if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
                        AdminLogger.security("VALIDATION", "Path traversal attempt blocked: " + filename + " from user: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid filename - path traversal"));
                        return;
                    }
                    
                    // Sanitize filename - only allow safe characters
                    String safeFilename = filename.replaceAll("[^a-zA-Z0-9._-]", "_");
                    if (!safeFilename.equals(filename)) {
                        AdminLogger.security("VALIDATION", "Filename sanitized: " + filename + " -> " + safeFilename);
                        filename = safeFilename;
                    }

                    // SECURITY: Validate file size
                    long expectedSize;
                    try {
                        expectedSize = Long.parseLong(size);
                    } catch (NumberFormatException e) {
                        AdminLogger.security("VALIDATION", "Invalid file size format: " + size + " from user: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid file size"));
                        return;
                    }
                    
                    if (expectedSize <= 0) {
                        AdminLogger.security("VALIDATION", "Invalid file size: " + expectedSize + " bytes from user: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:File size must be positive"));
                        return;
                    }
                    
                    if (expectedSize > MAX_FILE_SIZE) {
                        AdminLogger.security("VALIDATION", "File too large rejected: " + expectedSize + " bytes (max: " + MAX_FILE_SIZE + ") from user: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:File too large (max " + (MAX_FILE_SIZE / 1024 / 1024) + "MB)"));
                        return;
                    }

                    fileTransferSize.put(transferId, 0L);
                    fileExpectedSize.put(transferId, expectedSize);

                    System.out.println("[TRANSFER] Starting transfer: " + filename + " (size=" + expectedSize + " bytes)");

                    // Check target BEFORE opening file stream to avoid leaks
                    String targetToken = tokenPairs.get(senderToken);
                    if (targetToken == null) {
                        System.err.println("[SERVER] Target token not found for senderToken: " + senderToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                        return;
                    }
                    
                    Channel target = clients.get(targetToken);
                    if (target == null || !target.isActive()) {
                        System.err.println("[SERVER] Target client not connected. targetToken=" + targetToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                        return;
                    }

                    try {
                        File uploadsDir = new File(UPLOADS_DIR);
                        if (!uploadsDir.exists()) uploadsDir.mkdirs();
                        OutputStream fos = new FileOutputStream(new File(uploadsDir, filename));
                        activeFileStreams.put(transferId, fos);
                        activeFileNames.put(transferId, filename);
                        transferOwners.put(transferId, senderToken); // Track who owns this transfer
                        
                        // AUDIT: Log file transfer start
                        String clientIP = ctx.channel().remoteAddress().toString().split(":")[0];
                        AuditLogger.logFileSent(senderToken, filename, expectedSize, "PC", clientIP, true);
                        
                    } catch (Exception e) {

                        System.err.println("[TRANSFER] Failed to open file stream: " + e.getMessage());
                        
                        // AUDIT: Log failure
                        String clientIP = ctx.channel().remoteAddress().toString().split(":")[0];
                        AuditLogger.logFileSent(senderToken, filename, expectedSize, "PC", clientIP, false);
                        
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Failed to open file stream"));
                        return;

                    }

                    target.writeAndFlush(new TextWebSocketFrame(message));
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("OK:READY:" + transferId));
                } else {

                    System.err.println("[TRANSFER] Invalid FILE_INFO format: " + message);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid FILE_INFO format"));
                }

            } else if (message.startsWith("REGISTER_PAIR:")) {
                String[] parts = message.split(":", 4);
                if (parts.length >= 3) {
                    String androidToken = parts[1];
                    String pcToken = parts[2];
                    String sharedSecret = parts.length > 3 ? parts[3] : null;
                    
                    String androidUserId = getUserIdFromToken(androidToken);
                    String pcUserId = getUserIdFromToken(pcToken);
                    if (androidUserId == null || pcUserId == null) {

                        System.err.println("[PAIR] Invalid JWT in REGISTER_PAIR. androidToken=" + androidToken + ", pcToken=" + pcToken);

                        ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT token in REGISTER_PAIR"));
                        return;
                    }
                    tokenPairs.put(pcUserId, androidUserId);
                    tokenPairs.put(androidUserId, pcUserId);
                    savePairings(); // Save pairings to file
                    
                    // Track pair info for admin panel
                    PairManager.registerPair(pcUserId, androidUserId);
                    
                    AdminLogger.info("PAIR", "Registered pair: PC=" + pcUserId + " <-> Android=" + androidUserId);

                    Channel androidCh = clients.get(androidUserId);
                    Channel pcCh = clients.get(pcUserId);
                    
                    // Send pairing confirmation with shared secret if provided
                    if (sharedSecret != null && !sharedSecret.isEmpty()) {
                        System.out.println("[PAIR] Pairing with E2E encryption enabled");
                        if (androidCh != null) androidCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + pcUserId + ":" + sharedSecret));
                        if (pcCh != null) pcCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + androidUserId + ":" + sharedSecret));
                    } else {
                        System.out.println("[PAIR] Pairing without E2E encryption (legacy mode)");
                        if (androidCh != null) androidCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + pcUserId));
                        if (pcCh != null) pcCh.writeAndFlush(new TextWebSocketFrame("PAIR_REGISTERED:" + androidUserId));
                    }
                } else {

                    System.err.println("[PAIR] Invalid REGISTER_PAIR format: " + message);

                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid REGISTER_PAIR format"));
                }
            } else if (message.startsWith("FILE_END:")) {
                String[] parts = message.split(":", 2);
                String transferId = parts[1];

                OutputStream fos = activeFileStreams.remove(transferId);
                String fileName = activeFileNames.remove(transferId);
                String owner = transferOwners.remove(transferId);
                Long fileSize = fileExpectedSize.get(transferId);
                
                if (fos != null) {
                    try {
                        fos.close();
                        AdminLogger.info("TRANSFER", "File saved: " + fileName + " (" + (fileSize != null ? fileSize : 0) + " bytes, active: " + activeFileStreams.size() + "/" + MAX_ACTIVE_TRANSFERS + ")");
                        
                        // AUDIT: Log successful file transfer completion
                        String clientIP = ctx.channel().remoteAddress().toString().split(":")[0];
                        String targetToken = tokenPairs.get(senderToken);
                        String targetClient = targetToken != null ? "Android" : "Unknown";
                        long actualSize = fileTransferSize.getOrDefault(transferId, 0L);
                        AuditLogger.logFileTransfer(senderToken, fileName, actualSize, "PC", targetClient, clientIP, true, 
                            "Transfer completed successfully");
                        
                    } catch (Exception e) {
                        AdminLogger.error("TRANSFER", "Error closing file: " + e.getMessage());
                        
                        // AUDIT: Log failure
                        String clientIP = ctx.channel().remoteAddress().toString().split(":")[0];
                        AuditLogger.logFileTransfer(senderToken, fileName, fileSize != null ? fileSize : 0, "PC", "Android", clientIP, false, 
                            "Error: " + e.getMessage());
                    }
                } else {
                    AdminLogger.warn("TRANSFER", "FILE_END received but no active stream found for transferId: " + transferId);
                    
                    // AUDIT: Log failure
                    String clientIP = ctx.channel().remoteAddress().toString().split(":")[0];
                    AuditLogger.logFileTransfer(senderToken, fileName, fileSize != null ? fileSize : 0, "PC", "Android", clientIP, false, 
                        "No active stream found");
                }
                
                // Update pair statistics
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken != null && fileSize != null) {
                    PairManager.recordFileTransfer(senderToken, targetToken, fileSize);
                    PairManager.updatePairActivity(senderToken, targetToken);
                }
                
                fileTransferSize.remove(transferId);
                fileExpectedSize.remove(transferId);

                if (targetToken == null) {
                    AdminLogger.error("TRANSFER", "Target token not found for FILE_END. senderToken=" + senderToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target not connected"));
                    return;
                }
                Channel target = clients.get(targetToken);
                if (target == null || !target.isActive()) {
                    AdminLogger.error("TRANSFER", "Target client not connected for FILE_END. targetToken=" + targetToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Target client not connected"));
                    return;
                }

                target.writeAndFlush(new TextWebSocketFrame("FILE_END:" + transferId));
                ctx.channel().writeAndFlush(new TextWebSocketFrame("FILE_RECEIVED:" + transferId));
                AdminLogger.info("TRANSFER", "FILE_END sent to PC, FILE_RECEIVED sent to Android");
            } else if (message.equals("DELETE_PAIRING")) {
                String pairToken = tokenPairs.remove(senderToken);
                if (pairToken != null) {
                    tokenPairs.remove(pairToken);
                    savePairings(); // Save pairings after deletion
                    
                    // Unregister from PairManager
                    PairManager.unregisterPair(senderToken, pairToken);
                    
                    Channel pairCh = clients.get(pairToken);
                    if (pairCh != null) {
                        pairCh.writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:" + senderToken));
                        pairCh.writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
                    }
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:SUCCESS"));

                    AdminLogger.info("PAIR", "Pairing deleted by user: " + senderToken + " <-> " + pairToken);

                } else {
                    AdminLogger.warn("PAIR", "Delete pairing failed - no pairing found for: " + senderToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:No pairing found"));
                }
            } else if (message.startsWith("FILE_RECEIVED:")) {
                String[] parts = message.split(":", 2);
                String transferId = parts[1];
                
                System.out.println("[TRANSFER] <<< FILE_RECEIVED from PC (transferId=" + transferId + ")");
                
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

                // NOW send SLOT_FREE to the sender (Android) - PC has confirmed receipt!
                target.writeAndFlush(new TextWebSocketFrame("SLOT_FREE"));
                System.out.println("[TRANSFER] >>> SLOT_FREE sent to Android (active: " + activeFileStreams.size() + "/20)");

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
                    // Check if Android is actually online
                    Channel androidChannel = clients.get(androidToken);
                    
                    if (androidChannel != null && androidChannel.isActive()) {
                        System.out.println("[PAIR] Forwarding IS_PAIRED check to Android for pcToken=" + pcToken);
                        
                        // Forward to Android and wait for confirmation
                        androidChannel.writeAndFlush(new TextWebSocketFrame("IS_PAIRED:" + pcToken));
                        pendingPairChecks.put(pcToken, ctx.channel());
                    } else {
                        System.out.println("[PAIR] Pair exists but Android offline for pcToken=" + pcToken);
                        ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
                    }
                } else {
                    System.out.println("[PAIR] No pair for pcToken=" + pcToken);
                    ctx.channel().writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
                }
            } else if (message.startsWith("PAIR_CONFIRMED:")) {
                // Android confirmed pairing
                String[] parts = message.split(":");
                if (parts.length >= 3) {
                    String androidToken = parts[1];
                    String pcToken = parts[2];
                    
                    System.out.println("[PAIR] Received PAIR_CONFIRMED from Android: androidToken=" + androidToken + ", pcToken=" + pcToken);
                    
                    // Restore pairing in memory
                    tokenPairs.put(pcToken, androidToken);
                    savePairings();
                    
                    // Notify PC client
                    Channel pcChannel = pendingPairChecks.remove(pcToken);
                    if (pcChannel != null && pcChannel.isActive()) {
                        pcChannel.writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:YES"));
                        System.out.println("[PAIR] Sent PAIR_STATUS:YES to PC");
                    }
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
                
                // Forward binary data to target (already validated above)
                ByteBuf toSend = Unpooled.buffer(prefixBytes.length + chunk.length);
                toSend.writeBytes(prefixBytes);
                toSend.writeBytes(chunk);
                target.writeAndFlush(new BinaryWebSocketFrame(toSend));

                System.out.println("[TRANSFER] Forwarded FILE_DATA chunk to target: " + targetToken +
                        ", transferId=" + transferId + ", chunkSize=" + chunk.length);
            } else {

                System.err.println("[SERVER] Unknown binary prefix received: " + prefix);

            }
            buffer.release();
        }

        private String getUserIdFromToken(String jwtToken) {
            try {
                // First try as standard JWT
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                return JWT.require(algorithm).acceptLeeway(60).build().verify(jwtToken).getSubject();
            } catch (com.auth0.jwt.exceptions.TokenExpiredException e) {
                System.err.println("[JWT] Token expired: " + jwtToken.substring(0, Math.min(20, jwtToken.length())) + "...");
                return null; // Token expired - client needs to re-pair
            } catch (Exception e) {
                // If not standard JWT, try as simplified token
                if (jwtToken.startsWith("JWT_") && jwtToken.contains("_")) {
                    String[] parts = jwtToken.split("_", 3);
                    if (parts.length >= 2) {
                        String userId = parts[1];
                        System.out.println("[JWT] Using simplified token format, userId=" + userId);
                        return userId;
                    }
                }
                
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

                AdminLogger.info("DISCONNECT", "Client disconnected: userId=" + toRemove);
                
                // Clean up active file streams ONLY for this specific user
                int cleanedStreams = 0;
                java.util.Iterator<Map.Entry<String, OutputStream>> iterator = activeFileStreams.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<String, OutputStream> entry = iterator.next();
                    String transferId = entry.getKey();
                    String owner = transferOwners.get(transferId);
                    
                    // Only clean up streams that belong to THIS disconnected user
                    if (toRemove.equals(owner)) {
                        try {
                            entry.getValue().close();
                            cleanedStreams++;
                            System.out.println("[CLEANUP] Closed active stream for transferId: " + transferId + " (owner: " + owner + ")");
                        } catch (Exception e) {
                            System.err.println("[CLEANUP] Error closing stream: " + e.getMessage());
                        }
                        
                        iterator.remove();
                        activeFileNames.remove(transferId);
                        transferOwners.remove(transferId);
                        fileTransferSize.remove(transferId);
                        fileExpectedSize.remove(transferId);
                    }
                }
                
                if (cleanedStreams > 0) {
                    System.out.println("[CLEANUP] Cleaned " + cleanedStreams + " active streams for disconnected user: " + toRemove + " (active: " + activeFileStreams.size() + "/" + MAX_ACTIVE_TRANSFERS + ")");
                } else {
                    System.out.println("[CLEANUP] No active streams found for disconnected user: " + toRemove);
                }

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
        
        /**
         * Save pairings to file for persistence across server restarts
         */
        private static void savePairings() {
            try {
                File file = new File("pairings.json");
                com.google.gson.Gson gson = new com.google.gson.Gson();
                String json = gson.toJson(tokenPairs);
                
                try (java.io.FileWriter writer = new java.io.FileWriter(file)) {
                    writer.write(json);
                }
                
                AdminLogger.info("PERSISTENCE", "Saved " + tokenPairs.size() + " pairings to pairings.json");
            } catch (Exception e) {
                AdminLogger.error("PERSISTENCE", "Error saving pairings: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        /**
         * Load pairings from file on server startup
         */
        private static void loadPairings() {
            try {
                File file = new File("pairings.json");
                if (!file.exists()) {
                    AdminLogger.info("PERSISTENCE", "No pairings file found, starting fresh");
                    return;
                }
                
                com.google.gson.Gson gson = new com.google.gson.Gson();
                java.io.FileReader reader = new java.io.FileReader(file);
                java.lang.reflect.Type type = new com.google.gson.reflect.TypeToken<java.util.Map<String, String>>(){}.getType();
                Map<String, String> loaded = gson.fromJson(reader, type);
                reader.close();
                
                if (loaded != null) {
                    tokenPairs.putAll(loaded);
                    AdminLogger.info("PERSISTENCE", "Loaded " + loaded.size() + " pairings from pairings.json");
                    
                    // Reconstruct PairManager from loaded pairings
                    for (Map.Entry<String, String> entry : loaded.entrySet()) {
                        String key = entry.getKey();
                        String value = entry.getValue();
                        // Only register once per pair (not for both directions)
                        if (key.compareTo(value) < 0) {
                            PairManager.registerPair(key, value);
                        }
                    }
                }
            } catch (Exception e) {
                AdminLogger.error("PERSISTENCE", "Error loading pairings: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}