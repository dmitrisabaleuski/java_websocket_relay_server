package org.example;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
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
import static org.example.ServerSecret.SECRET;

public class RelayWebSocketServer extends WebSocketServer {

    private final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private final Map<String, Set<WebSocket>> clients = new ConcurrentHashMap<>();
    private final Map<WebSocket, Boolean> receivingFile = new ConcurrentHashMap<>();
    private final ScheduledExecutorService pingScheduler = Executors.newSingleThreadScheduledExecutor();

    private final Map<String, Long> fileTransferSize = new ConcurrentHashMap<>();
    private final Map<String, Long> fileExpectedSize = new ConcurrentHashMap<>();
    private final Map<String, OutputStream> activeFileStreams = new ConcurrentHashMap<>();
    private final Map<String, String> activeFileNames = new ConcurrentHashMap<>();

    public RelayWebSocketServer(int port) {
        super(new InetSocketAddress(port), Collections.singletonList(new org.java_websocket.drafts.Draft_6455(Collections.emptyList(), 128 * 1024 * 1024)));
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
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress() +
                ", code: " + code + ", reason: " + reason + ", remote: " + remote);
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

            String[] parts = message.split(":", 5);
            if (parts.length >= 4) {
                String transferId = parts[1];
                fileTransferSize.put(transferId, 0L);
                String filename = parts[2];
                String size = parts[3];
                String tokenFromMessage = parts[4];

                long expectedSize = Long.parseLong(size);
                fileTransferSize.put(transferId, 0L);
                fileExpectedSize.put(transferId, expectedSize);

                try {
                    File uploadsDir = new File("uploads");
                    if (!uploadsDir.exists()) uploadsDir.mkdir();
                    OutputStream fos = new FileOutputStream(new File(uploadsDir, filename));
                    activeFileStreams.put(transferId, fos);
                    activeFileNames.put(transferId, filename);
                    System.out.println("Opened file stream for transferId=" + transferId + ", file=" + filename);
                } catch (Exception e) {
                    System.err.println("Failed to open file stream: " + e.getMessage());
                }

                String targetToken = tokenPairs.get(senderToken);
                Set<WebSocket> targets = clients.get(targetToken);
                if (targets != null && !targets.isEmpty()) {
                    for (WebSocket target : targets) {
                        if (target.isOpen()) {
                            target.send(message);
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

                boolean changed = false;
                if (!pcUserId.equals(tokenPairs.get(androidUserId)) || !androidUserId.equals(tokenPairs.get(pcUserId))) {
                    tokenPairs.put(pcUserId, androidUserId);
                    tokenPairs.put(androidUserId, pcUserId);
                    changed = true;
                    System.out.println("Registered pair: PC " + pcUserId + " <-> Android " + androidUserId);
                }

                Set<WebSocket> androidConns = clients.get(androidUserId);
                Set<WebSocket> pcConns = clients.get(pcUserId);

                if (androidConns != null) {
                    for (WebSocket androidConn : androidConns) {
                        if (androidConn.isOpen()) {
                            androidConn.send("PAIR_REGISTERED:" + pcUserId);
                        }
                    }
                }
                if (pcConns != null) {
                    for (WebSocket pcConn : pcConns) {
                        if (pcConn.isOpen()) {
                            pcConn.send("PAIR_REGISTERED:" + androidUserId);
                        }
                    }
                }
                if (!changed) {
                    System.out.println("REGISTER_PAIR ignored: same pairing already exists");
                }
            } else {
                conn.send("ERROR:Invalid REGISTER_PAIR format");
            }
        } else if (message.startsWith("FILE_END:")) {
            String[] parts = message.split(":", 2);
            String transferId = parts[1];
            Long total = fileTransferSize.get(transferId);
            Long expected = fileExpectedSize.get(transferId);
            System.out.println("FILE_END for transferId=" + transferId + ", total received bytes=" + total +
                    (expected != null ? (", expected=" + expected) : ""));

            OutputStream fos = activeFileStreams.remove(transferId);
            String fileName = activeFileNames.remove(transferId);
            if (fos != null) {
                try {
                    fos.close();
                    System.out.println("File saved: " + fileName);
                } catch (Exception e) {
                    System.err.println("Error closing file: " + e.getMessage());
                }
            } else {
                System.err.println("No file stream for transferId=" + transferId);
            }

            fileTransferSize.remove(transferId);
            fileExpectedSize.remove(transferId);

            String targetToken = tokenPairs.get(senderToken);
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("FILE_END:" + transferId);
                    }
                }
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
                            pairConn.send("PAIR_STATUS:NO");
                        }
                    }
                }
                conn.send("PAIR_DELETED:SUCCESS");
                System.out.println("Deleted pairing for: " + senderToken + " and " + pairToken);
            } else {
                conn.send("ERROR:No pairing found");
            }
        } else if (message.startsWith("FILE_RECEIVED:")) {
            String[] parts = message.split(":", 2);
            String transferId = parts[1];
            String targetToken = tokenPairs.get(senderToken);
            Set<WebSocket> targets = clients.get(targetToken);
            if (targets != null && !targets.isEmpty()) {
                for (WebSocket target : targets) {
                    if (target.isOpen()) {
                        target.send("FILE_RECEIVED:" + transferId);
                    }
                }
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
        } else if (message.startsWith("IS_PAIRED:")) {
            String pcToken = message.substring("IS_PAIRED:".length()).trim();
            String androidToken = tokenPairs.get(pcToken);
            if (androidToken != null) {
                conn.send("PAIR_STATUS:YES");
            } else {
                conn.send("PAIR_STATUS:NO");
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
            return null;
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        try {
            ByteBuffer duplicate = message.duplicate();
            duplicate.rewind();

            byte[] prefixBytes = new byte[64];
            duplicate.get(prefixBytes);
            String prefix = new String(prefixBytes, StandardCharsets.UTF_8).trim();

            if (prefix.startsWith("FILE_DATA:")) {
                String transferId = prefix.substring("FILE_DATA:".length()).trim();
                int dataLen = duplicate.remaining();
                String senderToken = null;
                fileTransferSize.merge(transferId, (long)dataLen, Long::sum);
                Long expected = fileExpectedSize.get(transferId);
                System.out.println("Received FILE_DATA for transferId=" + transferId +
                        ", chunk=" + dataLen +
                        ", total=" + fileTransferSize.get(transferId) +
                        (expected != null ? (", expected=" + expected) : ""));
                byte[] chunk = new byte[dataLen];
                duplicate.get(chunk);
                OutputStream fos = activeFileStreams.get(transferId);
                if (fos != null) {
                    fos.write(chunk);
                } else {
                    System.err.println("No file stream for transferId=" + transferId + " (chunk dropped!)");
                }

                for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
                    if (entry.getValue().contains(conn)) {
                        senderToken = entry.getKey();
                        break;
                    }
                }

                String targetToken = tokenPairs.get(senderToken);
                Set<WebSocket> targets = clients.get(targetToken);
                if (targets != null && !targets.isEmpty()) {
                    for (WebSocket target : targets) {
                        if (target.isOpen()) {
                            ByteBuffer toSend = ByteBuffer.allocate(prefixBytes.length + chunk.length);
                            toSend.put(prefixBytes);
                            toSend.put(chunk);
                            toSend.flip();
                            target.send(toSend);
                        }
                    }
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
        System.err.println("Error: " + ex.getMessage());
        ex.printStackTrace();
        /*if (conn != null) {
            System.err.println("Error from client: " + conn.getRemoteSocketAddress());
        }
        ex.printStackTrace();*/
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
