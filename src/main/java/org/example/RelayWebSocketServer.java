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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class RelayWebSocketServer extends WebSocketServer {

    private final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private final Map<String, Set<WebSocket>> clients = new ConcurrentHashMap<>();
    private final Map<WebSocket, Boolean> receivingFile = new ConcurrentHashMap<>();
    private final ScheduledExecutorService pingScheduler = Executors.newSingleThreadScheduledExecutor();
    private static final String SECRET = "eY9xh9F!j$3Kz0@VqLu7pT1cG2mNwqAr";

    public RelayWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection: " + conn.getRemoteSocketAddress());
        System.out.println("Handshake headers: " + handshake.iterateHttpFields());

        String authHeader = handshake.getFieldValue("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("Missing or invalid Authorization header, closing connection");
            conn.send("ERROR:Missing or invalid Authorization header");
            conn.close(1008, "Unauthorized");
            return;
        }

        String jwtToken = authHeader.substring("Bearer ".length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm).acceptLeeway(60).build();
            DecodedJWT jwt = verifier.verify(jwtToken);
            String userId = jwt.getSubject();
            System.out.println("Client connected: " + userId);

            clients.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(conn);
            conn.send("REGISTERED:" + userId);

            System.out.println("Registered userId (from JWT header): " + userId);
        } catch (Exception e) {
            conn.send("ERROR:Invalid JWT token");
            System.err.println("Invalid JWT: " + e.getMessage());
            conn.close(1008, "Unauthorized");
        }
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress() + ", code: " + code + ", reason: " + reason);

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

            String pairToken = tokenPairs.remove(disconnectedToken);

            if (pairToken != null) {
                tokenPairs.remove(pairToken);

                Set<WebSocket> pairConns = clients.get(pairToken);
                if (pairConns != null) {
                    for (WebSocket pairConn : pairConns) {
                        if (pairConn.isOpen()) {
                            pairConn.send("PAIR_DISCONNECTED:" + disconnectedToken);
                            System.out.println("Notified " + pairToken + " about disconnection of " + disconnectedToken);
                        }
                    }
                }
            }
        }

        receivingFile.remove(conn);
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        String senderToken = null;
        for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
            if (entry.getValue().contains(conn)) {
                senderToken = entry.getKey();

                System.out.println("Received message from " + senderToken + ": " + message);

                break;
            }
        }

        if (senderToken == null) {
            conn.send("ERROR:Unknown sender - client not registered");
            return;
        }

        if (message.startsWith("FILE_INFO:")) {
            System.out.println("Processing FILE_INFO from " + senderToken + ": " + message);

            String[] parts = message.split(":", 4);
            if (parts.length >= 4) {
                String filename = parts[1];
                String size = parts[2];
                String tokenFromMessage = parts[3];

                String targetToken = tokenPairs.get(senderToken);
                Set<WebSocket> targets = clients.get(targetToken);
                if (targets != null && !targets.isEmpty()) {
                    for (WebSocket target : targets) {
                        if (target.isOpen()) {
                            target.send(message);
                            receivingFile.put(target, true);
                        }
                    }
                } else {
                    conn.send("ERROR:Target not connected");
                }
            } else {
                conn.send("ERROR:Invalid FILE_INFO format");
            }
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

                System.out.println("Registered pair: PC " + pcUserId + " <-> Android " + androidUserId);

                Set<WebSocket> androidConns = clients.get(androidUserId);
                Set<WebSocket> pcConns = clients.get(pcUserId);

                if (androidConns != null) {
                    for (WebSocket androidConn : androidConns) {
                        if (androidConn.isOpen()) {
                            androidConn.send("PAIR_REGISTERED:" + pcUserId);
                        }
                    }
                }

                if (pcConns == null) {
                    System.err.println("PC connection for userId " + pcUserId + " is null!");
                } else {
                    for (WebSocket pcConn : pcConns) {
                        if (pcConn.isOpen()) {
                            pcConn.send("PAIR_REGISTERED:" + androidUserId);
                            System.out.println("Sent PAIR_REGISTERED to PC " + pcUserId);
                        }
                    }
                }
            } else {
                conn.send("ERROR:Invalid REGISTER_PAIR format");
            }
        } else if (message.equals("FILE_END")) {
            String targetToken = tokenPairs.get(senderToken);
            if (targetToken == null) {
                conn.send("ERROR:Target not paired yet (missing target token)");
                System.err.println("ERROR: No pair found for sender token: " + senderToken);
                return;
            }
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("FILE_END");
                        receivingFile.put(target, false);
                    }
                }
            } else {
                conn.send("ERROR:Target not connected");
            }
        } else if (message.equals("DELETE_PAIRING")) {
            String pairToken = tokenPairs.remove(senderToken);
            if (pairToken != null) {
                tokenPairs.remove(pairToken);
                Set<WebSocket> pairConns = clients.get(pairToken);
                if (pairConns != null) {
                    for (WebSocket pairConn : pairConns) {
                        if (pairConn.isOpen()) {
                            pairConn.send("PAIR_DELETED:" + senderToken);
                        }
                    }
                }
                conn.send("PAIR_DELETED:SUCCESS");
                System.out.println("Deleted pairing for: " + senderToken + " and " + pairToken);
            } else {
                conn.send("ERROR:No pairing found");
            }
        } else if (message.equals("FILE_RECEIVED")) {
            String targetToken = tokenPairs.get(senderToken);
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("FILE_RECEIVED");
                    }
                }
            } else {
                conn.send("ERROR:Target not connected");
            }
        } else if (message.startsWith("FILE_LIST:")) {
            String fileListJson = message.substring("FILE_LIST:".length());

            String targetToken = tokenPairs.get(senderToken);
            if (targetToken == null) {
                conn.send("ERROR:No paired target for sender");
                return;
            }

            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("FILE_LIST:" + fileListJson);
                        System.out.println("Forwarded FILE_LIST from " + senderToken + " to " + targetToken);
                    }
                }
            } else {
                conn.send("ERROR:Target client not connected");
            }
        } else if (message.startsWith("DELETE_FILE:")) {
            String fileId = message.substring("DELETE_FILE:".length());

            String targetToken = tokenPairs.get(senderToken);
            if (targetToken == null) {
                conn.send("ERROR:No paired target for sender");
                return;
            }

            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("DELETE_FILE:" + fileId);
                        System.out.println("Forwarded DELETE_FILE from " + senderToken + " to " + targetToken + " for fileId: " + fileId);
                    }
                }
            } else {
                conn.send("ERROR:Target client not connected");
            }
        } else if (message.equals("GET_FILES")) {
            String targetToken = tokenPairs.get(senderToken);
            if (targetToken == null) {
                conn.send("ERROR:No paired target for sender");
                System.err.println("ERROR: No pair found for sender token: " + senderToken);
                return;
            }
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("GET_FILES");
                        System.out.println("Forwarded GET_FILES from " + senderToken + " to " + targetToken);
                    }
                }
            } else {
                conn.send("ERROR:Target client not connected");
            }
        } else {
            conn.send("ERROR:Unknown command");
        }

    }

    private String getUserIdFromToken(String jwtToken) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm).acceptLeeway(60).build();
            DecodedJWT jwt = verifier.verify(jwtToken);
            return jwt.getSubject();
        } catch (Exception e) {
            System.err.println("Invalid JWT token in REGISTER_PAIR: " + e.getMessage());
            return null;
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        try {
            ByteBuffer duplicate = message.duplicate();
            duplicate.rewind();

            byte[] prefixBytes = new byte[9];
            duplicate.get(prefixBytes);
            String prefix = new String(prefixBytes, StandardCharsets.UTF_8);

            if ("FILE_DATA".equals(prefix)) {
                String senderToken = null;
                for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
                    if (entry.getValue().contains(conn)) {
                        senderToken = entry.getKey();
                        break;
                    }
                }
                if (senderToken == null) {
                    System.err.println("Unknown sender for binary message");
                    return;
                }

                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {
                    System.err.println("No paired target token found for sender: " + senderToken);
                    return;
                }

                System.out.println("Received FILE_DATA from " + senderToken + " for " + targetToken + " (" + message.remaining() + " bytes)");

                Set<WebSocket> targets = clients.get(targetToken);
                if (targets != null && !targets.isEmpty()) {
                    for (WebSocket target : targets) {
                        if (target.isOpen() && receivingFile.getOrDefault(target, false)) {
                            ByteBuffer toSend = message.duplicate();
                            toSend.rewind();
                            target.send(toSend);
                        }
                    }
                } else {
                    System.err.println("Target not connected or not receiving file");
                }
            } else {
                System.err.println("Unknown binary prefix received on server: " + prefix);
            }
        } catch (Exception e) {
            System.err.println("Error while processing binary message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        if (conn != null) {
            System.err.println("Error from client: " + conn.getRemoteSocketAddress());
        }
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("Relay WebSocket Server started on port " + getPort());

        pingScheduler.scheduleAtFixedRate(() -> {
            for (Set<WebSocket> wsSet : clients.values()) {
                for (WebSocket client : wsSet) {
                    System.out.println("Sending ping to " + client.getRemoteSocketAddress());
                    if (client.isOpen()) {
                        try {
                            client.sendPing();
                        } catch (Exception e) {
                            System.err.println("Ping failed: " + e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            }
        }, 0, 30, TimeUnit.SECONDS);
    }

    @Override
    public void stop(int timeout) throws InterruptedException {
        super.stop(timeout);
        pingScheduler.shutdownNow();
    }

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        RelayWebSocketServer server = new RelayWebSocketServer(port);
        server.start();
    }
}
