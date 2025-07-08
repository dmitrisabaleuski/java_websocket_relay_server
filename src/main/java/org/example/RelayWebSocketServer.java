package org.example;

import org.java_websocket.server.WebSocketServer;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class RelayWebSocketServer extends WebSocketServer {

    // Token Map -> WebSocket multiconnection
    private final Map<String, Set<WebSocket>> clients = new ConcurrentHashMap<>();

    public RelayWebSocketServer(int port) {
        super(new InetSocketAddress(port));
    }

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        RelayWebSocketServer server = new RelayWebSocketServer(port);
        server.start();
        System.out.println("Server started on port " + port);
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection: " + conn.getRemoteSocketAddress());
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress());

        clients.forEach((token, conns) -> conns.remove(conn));

        clients.entrySet().removeIf(entry -> entry.getValue().isEmpty());
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        if (message.startsWith("TOKEN:")) {
            String token = message.substring(6);

            clients.computeIfAbsent(token, k -> ConcurrentHashMap.newKeySet()).add(conn);
            conn.send("REGISTERED:" + token);
            System.out.println("Client registered with token: " + token);

        } else if (message.startsWith("SEND:")) {
            String[] parts = message.split(":", 3);
            if (parts.length == 3) {
                String targetToken = parts[1];
                String payload = parts[2];

                Set<WebSocket> conns = clients.get(targetToken);
                if (conns != null && !conns.isEmpty()) {
                    for (WebSocket client : conns) {
                        if (!client.equals(conn)) {
                            client.send("RECEIVED:" + payload);
                        }
                    }
                    conn.send("DELIVERED");
                } else {
                    conn.send("ERROR:Target not connected");
                }
            } else {
                conn.send("ERROR:Invalid SEND format");
            }
        } else if (message.startsWith("FILENAME:")) {
            String fileName = message.substring("FILENAME:".length());

            // Search sender token
            String senderToken = null;
            for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
                if (entry.getValue().contains(conn)) {
                    senderToken = entry.getKey();
                    break;
                }
            }

            if (senderToken != null) {
                Set<WebSocket> conns = clients.get(senderToken);
                for (WebSocket client : conns) {
                    if (!client.equals(conn)) {
                        client.send(message);
                    }
                }
            }
        } else {
            conn.send("ERROR:Unknown command");
        }
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        String senderToken = null;
        for (Map.Entry<String, Set<WebSocket>> entry : clients.entrySet()) {
            if (entry.getValue().contains(conn)) {
                senderToken = entry.getKey();
                break;
            }
        }

        clients.values().forEach(set -> {
            set.forEach(client -> {
                if (!client.equals(conn)) {
                    client.send(message);
                }
            });
        });
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.err.println("Error on connection " + (conn != null ? conn.getRemoteSocketAddress() : "unknown") + ":");
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("Relay WebSocket Server started on port " + getPort());
    }
}
