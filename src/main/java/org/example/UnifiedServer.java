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

public class UnifiedServer {

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
    
    // Admin panel configuration
    private static final String ADMIN_USERNAME = System.getenv().getOrDefault("ADMIN_USERNAME", "admin");
    private static final String ADMIN_PASSWORD = System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123");
    private static final Map<String, String> adminSessions = new ConcurrentHashMap<>();
    private static final java.util.Queue<String> serverLogs = new java.util.LinkedList<>();
    private static final int MAX_LOGS = 1000;

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        File uploads = new File(UPLOADS_DIR);
        if (!uploads.exists()) uploads.mkdirs();
        
        // Initialize admin logging
        logAdmin("INFO", "SYSTEM", "Server starting on port " + port);

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

            System.out.println("[SERVER] Netty server started on port " + port);
            
            // Start heartbeat timer
            startHeartbeatTimer();
            System.out.println("[SERVER] Heartbeat timer started with interval: " + HEARTBEAT_INTERVAL + "ms");

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
     * Send PING to all connected clients
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
    }

            static class UnifiedServerHandler extends SimpleChannelInboundHandler<Object> {
            private WebSocketServerHandshaker handshaker;
            private String userId;
            
            /**
             * Logs admin events to the server logs
             */
            private void logAdmin(String level, String source, String message) {
                String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
                String logEntry = String.format("[%s] %s [%s] %s", timestamp, level, source, message);
                
                synchronized (serverLogs) {
                    serverLogs.offer(logEntry);
                    if (serverLogs.size() > MAX_LOGS) {
                        serverLogs.poll();
                    }
                }
                
                System.out.println(logEntry);
            }

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
                } else if ("/api/stats".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleStatsRequest(ctx, req);
                } else if ("/api/clients".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleClientsRequest(ctx, req);
                } else if ("/api/logs".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleLogsRequest(ctx, req);
                } else if ("/admin".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleAdminPage(ctx, req);
                } else if ("/admin/login".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.POST) {
                    handleAdminLogin(ctx, req);
                } else if ("/admin/dashboard".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                    handleAdminDashboard(ctx, req);
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
        
        // Admin panel methods
        private void handleStatsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                JSONObject stats = new JSONObject();
                stats.put("totalClients", clients.size());
                stats.put("activeTransfers", activeFileStreams.size());
                stats.put("serverUptime", System.currentTimeMillis() - startTime);
                stats.put("totalFileTransfers", fileTransferSize.size());
                
                // Memory usage
                Runtime runtime = Runtime.getRuntime();
                long totalMemory = runtime.totalMemory();
                long freeMemory = runtime.freeMemory();
                long usedMemory = totalMemory - freeMemory;
                stats.put("memoryUsed", usedMemory);
                stats.put("memoryTotal", totalMemory);
                stats.put("memoryFree", freeMemory);
                
                ByteBuf content = Unpooled.copiedBuffer(stats.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "application/json");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
                logAdmin("INFO", "ADMIN", "Stats requested");
            } catch (Exception e) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }
        
        private void handleClientsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                JSONObject response = new JSONObject();
                JSONArray clientsArray = new JSONArray();
                
                for (Map.Entry<String, Channel> entry : clients.entrySet()) {
                    JSONObject client = new JSONObject();
                    client.put("userId", entry.getKey());
                    client.put("connected", entry.getValue().isActive());
                    client.put("remoteAddress", entry.getValue().remoteAddress().toString());
                    client.put("connectionTime", System.currentTimeMillis());
                    clientsArray.put(client);
                }
                
                response.put("clients", clientsArray);
                response.put("total", clients.size());
                
                ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "application/json");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
                logAdmin("INFO", "ADMIN", "Clients list requested");
            } catch (Exception e) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }
        
        private void handleLogsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                JSONObject response = new JSONObject();
                JSONArray logsArray = new JSONArray();
                
                synchronized (serverLogs) {
                    for (String log : serverLogs) {
                        logsArray.put(log);
                    }
                }
                
                response.put("logs", logsArray);
                response.put("total", serverLogs.size());
                
                ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(CONTENT_TYPE, "application/json");
                resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
                logAdmin("INFO", "ADMIN", "Logs requested");
            } catch (Exception e) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }
        
        private void handleAdminPage(ChannelHandlerContext ctx, FullHttpRequest req) {
            String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>HomeCloud Admin Panel</title>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .login-form { text-align: center; }
                        input[type="text"], input[type="password"] { padding: 12px; margin: 10px; width: 250px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
                        button { padding: 12px 30px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
                        button:hover { background: #0056b3; }
                        .error { color: red; margin: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>HomeCloud Admin Panel</h1>
                        <div class="login-form">
                            <h2>Login</h2>
                            <form id="loginForm">
                                <input type="text" id="username" placeholder="Username" required><br>
                                <input type="password" id="password" placeholder="Password" required><br>
                                <button type="submit">Login</button>
                            </form>
                            <div id="error" class="error"></div>
                        </div>
                    </div>
                    <script>
                        document.getElementById('loginForm').addEventListener('submit', async (e) => {
                            e.preventDefault();
                            const username = document.getElementById('username').value;
                            const password = document.getElementById('password').value;
                            
                            try {
                                const response = await fetch('/admin/login', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ username, password })
                                });
                                
                                if (response.ok) {
                                    const data = await response.json();
                                    localStorage.setItem('adminToken', data.token);
                                    window.location.href = '/admin/dashboard';
                                } else {
                                    document.getElementById('error').textContent = 'Invalid credentials';
                                }
                            } catch (error) {
                                document.getElementById('error').textContent = 'Login failed';
                            }
                        });
                    </script>
                </body>
                </html>
                """;
            
            ByteBuf content = Unpooled.copiedBuffer(html, CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(CONTENT_TYPE, "text/html; charset=UTF-8");
            resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            logAdmin("INFO", "ADMIN", "Admin page accessed");
        }
        
        private void handleAdminLogin(ChannelHandlerContext ctx, FullHttpRequest req) {
            try {
                String body = req.content().toString(CharsetUtil.UTF_8);
                JSONObject json = new JSONObject(body);
                String username = json.optString("username");
                String password = json.optString("password");
                
                if (ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password)) {
                    String sessionToken = java.util.UUID.randomUUID().toString();
                    adminSessions.put(sessionToken, username);
                    
                    JSONObject response = new JSONObject();
                    response.put("success", true);
                    response.put("token", sessionToken);
                    response.put("message", "Login successful");
                    
                    ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                    FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                    resp.headers().set(CONTENT_TYPE, "application/json");
                    resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                    
                    sendHttpResponse(ctx, req, resp);
                    logAdmin("INFO", "ADMIN", "Admin login successful: " + username);
                } else {
                    JSONObject response = new JSONObject();
                    response.put("success", false);
                    response.put("message", "Invalid credentials");
                    
                    ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                    FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED, content);
                    resp.headers().set(CONTENT_TYPE, "application/json");
                    resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                    
                    sendHttpResponse(ctx, req, resp);
                    logAdmin("WARN", "ADMIN", "Admin login failed: " + username);
                }
            } catch (Exception e) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
            }
        }
        
        private void handleAdminDashboard(ChannelHandlerContext ctx, FullHttpRequest req) {
            String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>HomeCloud Admin Dashboard</title>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                        .container { max-width: 1400px; margin: 0 auto; }
                        .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
                        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .stat-card h3 { margin: 0 0 15px 0; color: #333; }
                        .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
                        .clients-table { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                        .logs-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        table { width: 100%; border-collapse: collapse; }
                        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                        th { background: #f8f9fa; font-weight: bold; }
                        .refresh-btn { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 10px 0; }
                        .refresh-btn:hover { background: #218838; }
                        .logout-btn { padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; float: right; }
                        .logout-btn:hover { background: #c82333; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>HomeCloud Admin Dashboard</h1>
                            <button class="logout-btn" onclick="logout()">Logout</button>
                        </div>
                        
                        <div class="stats-grid">
                            <div class="stat-card">
                                <h3>Server Statistics</h3>
                                <div id="serverStats">Loading...</div>
                            </div>
                            <div class="stat-card">
                                <h3>Memory Usage</h3>
                                <div id="memoryStats">Loading...</div>
                            </div>
                            <div class="stat-card">
                                <h3>Active Transfers</h3>
                                <div id="transferStats">Loading...</div>
                            </div>
                        </div>
                        
                        <div class="clients-table">
                            <h3>Connected Clients</h3>
                            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
                            <div id="clientsTable">Loading...</div>
                        </div>
                        
                        <div class="logs-container">
                            <h3>Server Logs</h3>
                            <div id="logsContainer">Loading...</div>
                        </div>
                    </div>
                    
                    <script>
                        let refreshInterval;
                        
                        function refreshData() {
                            loadStats();
                            loadClients();
                            loadLogs();
                        }
                        
                        async function loadStats() {
                            try {
                                const response = await fetch('/api/stats');
                                const data = await response.json();
                                
                                document.getElementById('serverStats').innerHTML = `
                                    <div class="stat-value">${data.totalClients}</div>
                                    <div>Total Clients</div>
                                    <div class="stat-value">${Math.round(data.serverUptime / 1000 / 60)}m</div>
                                    <div>Uptime</div>
                                `;
                                
                                const memoryMB = Math.round(data.memoryUsed / 1024 / 1024);
                                const totalMB = Math.round(data.memoryTotal / 1024 / 1024);
                                document.getElementById('memoryStats').innerHTML = `
                                    <div class="stat-value">${memoryMB}MB</div>
                                    <div>Used Memory</div>
                                    <div class="stat-value">${totalMB}MB</div>
                                    <div>Total Memory</div>
                                    </div>
                                `;
                                
                                document.getElementById('transferStats').innerHTML = `
                                    <div class="stat-value">${data.activeTransfers}</div>
                                    <div>Active Transfers</div>
                                    <div class="stat-value">${data.totalFileTransfers}</div>
                                    <div>Total Transfers</div>
                                `;
                            } catch (error) {
                                console.error('Error loading stats:', error);
                            }
                        }
                        
                        async function loadClients() {
                            try {
                                const response = await fetch('/api/clients');
                                const data = await response.json();
                                
                                let tableHtml = '<table><tr><th>User ID</th><th>Status</th><th>Remote Address</th><th>Connected</th></tr>';
                                data.clients.forEach(client => {
                                    const connected = client.connected ? '🟢 Online' : '🔴 Offline';
                                    const time = new Date(client.connectionTime).toLocaleTimeString();
                                    tableHtml += `<tr><td>${client.userId}</td><td>${connected}</td><td>${client.remoteAddress}</td><td>${time}</td></tr>`;
                                });
                                tableHtml += '</table>';
                                
                                document.getElementById('clientsTable').innerHTML = tableHtml;
                            } catch (error) {
                                console.error('Error loading clients:', error);
                            }
                        }
                        
                        async function loadLogs() {
                            try {
                                const response = await fetch('/api/logs');
                                const data = await response.json();
                                
                                let logsHtml = '<div style="max-height: 400px; overflow-y: auto;">';
                                data.logs.slice(-50).reverse().forEach(log => {
                                    logsHtml += `<div style="padding: 5px; border-bottom: 1px solid #eee;">${log}</div>`;
                                });
                                logsHtml += '</div>';
                                
                                document.getElementById('logsContainer').innerHTML = logsHtml;
                            } catch (error) {
                                console.error('Error loading logs:', error);
                            }
                        }
                        
                        function logout() {
                            localStorage.removeItem('adminToken');
                            window.location.href = '/admin';
                        }
                        
                        // Auto-refresh every 5 seconds
                        refreshInterval = setInterval(refreshData, 5000);
                        
                        // Initial load
                        refreshData();
                    </script>
                </body>
                </html>
                """;
            
            ByteBuf content = Unpooled.copiedBuffer(html, CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(CONTENT_TYPE, "text/html; charset=UTF-8");
            resp.headers().setInt(CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            logAdmin("INFO", "ADMIN", "Admin dashboard accessed");
        }
    }
}