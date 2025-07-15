package org.example;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class RelayWebSocketServer extends WebSocketServer {

    private final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private final Map<String, Set<WebSocket>> clients = new ConcurrentHashMap<>();
    private final Map<String, TransferSession> transfers = new ConcurrentHashMap<>();
    private static final String SECRET = "eY9xh9F!j$3Kz0@VqLu7pT1cG2mNwqAr";

    public RelayWebSocketServer(int port) {
        super(new InetSocketAddress(port));
        setConnectionLostTimeout(120);
    }

    static class TransferSession {
        public final String transferId;
        public final String senderToken;
        public final String targetToken;
        public final WebSocket senderConn;
        public final WebSocket targetConn;
        public final String fileName;
        public final long fileSize;
        public long bytesTransferred = 0;
        public boolean ended = false;

        public TransferSession(String transferId, String senderToken, String targetToken, WebSocket senderConn, WebSocket targetConn, String fileName, long fileSize) {
            this.transferId = transferId;
            this.senderToken = senderToken;
            this.targetToken = targetToken;
            this.senderConn = senderConn;
            this.targetConn = targetConn;
            this.fileName = fileName;
            this.fileSize = fileSize;
        }
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        String authHeader = handshake.getFieldValue("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            conn.close(1008, "Unauthorized");
            return;
        }
        String jwtToken = authHeader.substring("Bearer ".length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm).acceptLeeway(60).build();
            DecodedJWT jwt = verifier.verify(jwtToken);
            String userId = jwt.getSubject();
            clients.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(conn);
        } catch (Exception e) {
            conn.close(1008, "Unauthorized");
        }
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        String disconnectedToken = null;
        for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
            if (entry.getValue().contains(conn)) {
                disconnectedToken = entry.getKey();
                entry.getValue().remove(conn);
                if (entry.getValue().isEmpty()) {
                    clients.remove(disconnectedToken);
                }
                break;
            }
        }
        if (disconnectedToken != null) {
            clients.remove(disconnectedToken);
            tokenPairs.remove(disconnectedToken);
        }
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        String senderToken = null;
        for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
            if (entry.getValue().contains(conn)) {
                senderToken = entry.getKey();
                break;
            }
        }
        if (senderToken == null) {
            conn.send("ERROR:Unknown sender - client not registered");
            return;
        }

        if (message.startsWith("FILE_INFO:")) {
            String[] parts = message.split(":", 5);
            if (parts.length < 5) return;
            String transferId = parts[1];
            String fileName = parts[2];
            long fileSize = Long.parseLong(parts[3]);
            String senderTokenFromMsg = parts[4];
            String targetToken = tokenPairs.get(senderToken);
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets == null || targets.isEmpty()) {
                conn.send("ERROR:Target not connected");
                return;
            }
            WebSocket targetConn = targets.iterator().next();
            transfers.put(transferId, new TransferSession(transferId, senderToken, targetToken, conn, targetConn, fileName, fileSize));
            targetConn.send(message);
        } else if (message.startsWith("REGISTER_PAIR:")) {
            String[] parts = message.split(":", 3);
            if (parts.length == 3) {
                String androidToken = parts[1];
                String pcToken = parts[2];
                String androidUserId = getUserIdFromToken(androidToken);
                String pcUserId = getUserIdFromToken(pcToken);
                if (androidUserId == null || pcUserId == null) {
                    conn.send("ERROR:Invalid JWT token in REGISTER_PAIR");
                    return;
                }
                tokenPairs.put(pcUserId, androidUserId);
                tokenPairs.put(androidUserId, pcUserId);
            }
        } else if (message.startsWith("FILE_END:")) {
            String[] parts = message.split(":", 2);
            if (parts.length < 2) return;
            String transferId = parts[1];
            TransferSession ts = transfers.get(transferId);
            if (ts != null && ts.targetConn.isOpen()) {
                ts.ended = true;
                ts.targetConn.send(message);
            }
        } else if (message.startsWith("FILE_RECEIVED:")) {
            String[] parts = message.split(":", 2);
            if (parts.length < 2) return;
            String transferId = parts[1];
            TransferSession ts = transfers.get(transferId);
            if (ts != null && ts.senderConn.isOpen()) {
                ts.senderConn.send(message);
            }
            transfers.remove(transferId);
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.err.println("WebSocket error: " + ex.getMessage());
        if (conn != null) {
            System.err.println("From connection: " + conn.getRemoteSocketAddress());
        }
        ex.printStackTrace();
    }

    @Override
    public void onStart() {

    }

    private String getUserIdFromToken(String jwtToken) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm).acceptLeeway(60).build();
            DecodedJWT jwt = verifier.verify(jwtToken);
            return jwt.getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        byte[] prefixBuf = new byte[64];
        message.get(prefixBuf);
        String prefix = new String(prefixBuf, StandardCharsets.UTF_8).trim();
        if (!prefix.startsWith("FILE_DATA:")) return;
        String transferId = prefix.substring("FILE_DATA:".length()).trim();
        TransferSession ts = transfers.get(transferId);
        if (ts != null && ts.targetConn.isOpen()) {
            ByteBuffer forwardBuf = ByteBuffer.allocate(64 + message.remaining());
            forwardBuf.put(prefixBuf);
            forwardBuf.put(message);
            forwardBuf.flip();
            ts.targetConn.send(forwardBuf);
            ts.bytesTransferred += forwardBuf.remaining();
        }
    }

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "10000"));
        RelayWebSocketServer server = new RelayWebSocketServer(port);
        server.start();
    }
}
