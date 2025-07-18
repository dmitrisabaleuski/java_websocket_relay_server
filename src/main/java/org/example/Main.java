package org.example;

public class Main {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));

        TokenHttpServer.start(port);

        RelayWebSocketServer server = new RelayWebSocketServer(port);
        server.start();
    }
}