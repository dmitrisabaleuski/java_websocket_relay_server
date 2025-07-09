package org.example;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class RelayWebSocketServer extends WebSocketServer {

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
        clients.entrySet().removeIf(entry -> entry.getValue().equals(conn));
        receivingFile.remove(conn);
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        if (message.startsWith("TOKEN:")) {
            String token = message.substring(6);
            clients.put(token, conn);
            conn.send("REGISTERED:" + token);
        } else if (message.startsWith("FILE_INFO:")) {
            for (WebSocket client : clients.values()) {
                if (!client.equals(conn)) {
                    client.send(message);
                    receivingFile.put(client, true);
                }
            }
        } else if (message.equals("FILE_END")) {
            for (WebSocket client : clients.values()) {
                if (!client.equals(conn)) {
                    client.send(message);
                    receivingFile.put(client, false);
                }
            }
        } else if (message.equals("FILE_RECEIVED")) {
            for (WebSocket client : clients.values()) {
                if (!client.equals(conn)) {
                    client.send(message);
                }
            }
        } else {
            conn.send("ERROR:Unknown command");
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        String prefix = new String(message.array(), 0, 9, StandardCharsets.UTF_8);
        if ("FILE_DATA".equals(prefix)) {
            for (WebSocket client : clients.values()) {
                if (!client.equals(conn) && receivingFile.getOrDefault(client, false)) {
                    client.send(message);
                }
            }
        } else {
            System.err.println("Unknown binary prefix received on server: " + prefix);
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

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        RelayWebSocketServer server = new RelayWebSocketServer(new InetSocketAddress(port).getPort());
        server.start();
    }
}
