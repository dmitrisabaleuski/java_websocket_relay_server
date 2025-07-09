package org.example;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class RelayWebSocketServer extends WebSocketServer {

    private final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private final Map<String, WebSocket> clients = new ConcurrentHashMap<>();
    private final Map<WebSocket, Boolean> receivingFile = new ConcurrentHashMap<>();
    private final ScheduledExecutorService pingScheduler = Executors.newSingleThreadScheduledExecutor();

    public RelayWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection: " + conn.getRemoteSocketAddress());
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress());

        String disconnectedToken = null;
        for (Map.Entry<String, WebSocket> entry : clients.entrySet()) {
            if (entry.getValue().equals(conn)) {
                disconnectedToken = entry.getKey();
                break;
            }
        }

        if (disconnectedToken != null) {
            clients.remove(disconnectedToken);

            String pairToken = tokenPairs.remove(disconnectedToken);

            if (pairToken != null) {
                tokenPairs.remove(pairToken);

                WebSocket pairConn = clients.get(pairToken);
                if (pairConn != null && pairConn.isOpen()) {
                    pairConn.send("PAIR_DISCONNECTED:" + disconnectedToken);
                    System.out.println("Notified " + pairToken + " about disconnection of " + disconnectedToken);
                }
            }
        }

        receivingFile.remove(conn);
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        if (message.startsWith("TOKEN:")) {
            String[] parts = message.split(":", 3);
            if (parts.length == 2) {
                String token = parts[1];
                clients.put(token, conn);
                conn.send("REGISTERED:" + token);
                System.out.println("Registered token: " + token);
            } else if (parts.length == 3) {
                String token = parts[1];
                String pairToken = parts[2];
                clients.put(token, conn);
                tokenPairs.put(token, pairToken);
                tokenPairs.put(pairToken, token);
                conn.send("REGISTERED:" + token);
                System.out.println("Registered token: " + token);
                System.out.println("Paired " + token + " with " + pairToken);

                WebSocket pairConn = clients.get(pairToken);
                if (pairConn != null && pairConn.isOpen()) {
                    conn.send("PAIR_REGISTERED:" + pairToken);
                    pairConn.send("PAIR_REGISTERED:" + token);
                }
            } else {
                conn.send("ERROR:Invalid TOKEN format, expected TOKEN:<token>:<pairToken>");
            }
            return;
        } else {
            String senderToken = null;
            for (Map.Entry<String, WebSocket> entry : clients.entrySet()) {
                if (entry.getValue().equals(conn)) {
                    senderToken = entry.getKey();
                    break;
                }
            }
            if (senderToken == null) {
                conn.send("ERROR:Unknown sender");
                return;
            }

            if (message.startsWith("FILE_INFO:")) {
                String[] parts = message.split(":", 3);
                if (parts.length == 3) {
                    String filename = parts[1];
                    String size = parts[2];
                    String targetToken = tokenPairs.get(senderToken);
                    WebSocket target = clients.get(targetToken);
                    if (target != null && target.isOpen()) {
                        target.send(message);
                        receivingFile.put(target, true);
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

                    tokenPairs.put(pcToken, androidToken);
                    tokenPairs.put(androidToken, pcToken);
                    System.out.println("Registered pair: PC " + pcToken + " <-> Android " + androidToken);

                    WebSocket androidConn = clients.get(androidToken);
                    WebSocket pcConn = clients.get(pcToken);

                    if (androidConn != null && androidConn.isOpen()) {
                        androidConn.send("PAIR_REGISTERED:" + pcToken);
                    }
                    if (pcConn != null && pcConn.isOpen()) {
                        pcConn.send("PAIR_REGISTERED:" + androidToken);
                    }
                } else {
                    conn.send("ERROR:Invalid REGISTER_PAIR format");
                }
            } else if (message.equals("FILE_END")) {
                System.out.println("senderToken: " + senderToken);
                System.out.println("Current tokenPairs map: " + tokenPairs);
                String targetToken = tokenPairs.get(senderToken);
                if (targetToken == null) {
                    conn.send("ERROR:Target not paired yet (missing target token)");
                    System.err.println("ERROR: No pair found for sender token: " + senderToken);
                    return;
                }
                System.out.println("targetToken: " + targetToken);
                WebSocket target = clients.get(targetToken);
                if (target != null && target.isOpen()) {
                    target.send("FILE_END");
                    receivingFile.put(target, false);
                } else {
                    conn.send("ERROR:Target not connected");
                }
            } else if (message.equals("FILE_RECEIVED")) {
                String targetToken = tokenPairs.get(senderToken);
                WebSocket target = clients.get(targetToken);
                if (target != null && target.isOpen()) {
                    target.send("FILE_RECEIVED");
                } else {
                    conn.send("ERROR:Target not connected");
                }
            } else {
                conn.send("ERROR:Unknown command");
            }
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
                for (Map.Entry<String, WebSocket> entry : clients.entrySet()) {
                    if (entry.getValue().equals(conn)) {
                        senderToken = entry.getKey();
                        break;
                    }
                }
                if (senderToken == null) {
                    System.err.println("Unknown sender for binary message");
                    return;
                }
                String targetToken = tokenPairs.get(senderToken);
                WebSocket target = clients.get(targetToken);
                if (target != null && target.isOpen() && receivingFile.getOrDefault(target, false)) {
                    ByteBuffer toSend = message.duplicate();
                    toSend.rewind();
                    target.send(toSend);
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
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("Relay WebSocket Server started on port " + getPort());

        pingScheduler.scheduleAtFixedRate(() -> {
            for (WebSocket client : clients.values()) {
                if (client.isOpen()) {
                    try {
                        client.sendPing();  // Send ping
                    } catch (Exception e) {
                        System.err.println("Ping failed: " + e.getMessage());
                        e.printStackTrace();
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
