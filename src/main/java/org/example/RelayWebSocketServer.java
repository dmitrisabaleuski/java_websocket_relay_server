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
import java.util.concurrent.ConcurrentHashMap;

public class RelayWebSocketServer extends WebSocketServer {

    private final Map<String, WebSocket> clients = new ConcurrentHashMap<>();

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
    }

    @Override
    public void onMessage(WebSocket webSocket, String message) {
        System.out.println("Получено текстовое сообщение (игнорируется): " + message);
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        System.out.println("Получено бинарное сообщение размером: " + message.remaining() + " байт");

        try {
            // Пример: сохраняем файл (можно настроить путь и имя файла)
            File file = new File("received_file_" + System.currentTimeMillis() + ".bin");
            FileOutputStream fos = new FileOutputStream(file);
            byte[] bytes = new byte[message.remaining()];
            message.get(bytes);
            fos.write(bytes);
            fos.close();

            System.out.println("Файл сохранён как: " + file.getAbsolutePath());
            conn.send("Файл успешно сохранён: " + file.getName());

        } catch (IOException e) {
            e.printStackTrace();
            conn.send("Ошибка при сохранении файла: " + e.getMessage());
        }
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("Relay WebSocket Server started on port " + getPort());
    }

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        RelayWebSocketServer server = new RelayWebSocketServer(new InetSocketAddress(port).getPort());
        server.start();
    }
}
