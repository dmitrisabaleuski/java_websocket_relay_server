package org.example;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

public class AdminHttpServer {
    
    private final HttpServer server;
    private final int port;
    
    public AdminHttpServer(int port) throws IOException {
        this.port = port;
        
        // На Render.com используем 0.0.0.0 для привязки ко всем интерфейсам
        String bindAddress = System.getenv().getOrDefault("BIND_ADDRESS", "0.0.0.0");
        InetSocketAddress address = new InetSocketAddress(bindAddress, port);
        
        this.server = HttpServer.create(address, 0);
        setupRoutes();
        
        // На Render.com используем больше потоков для обработки
        int threadPoolSize = Integer.parseInt(System.getenv().getOrDefault("HTTP_THREAD_POOL_SIZE", "20"));
        server.setExecutor(Executors.newFixedThreadPool(threadPoolSize));
    }
    
    private void setupRoutes() {
        // Главная страница админ-панели
        server.createContext("/admin", new AdminPanelHandler());
        
        // Статистика сервера в формате JSON
        server.createContext("/api/stats", new StatsApiHandler());
        
        // Список клиентов в формате JSON
        server.createContext("/api/clients", new ClientsApiHandler());
        
        // Логи сервера
        server.createContext("/api/logs", new LogsApiHandler());
        
        // Статические файлы (CSS, JS, изображения)
        server.createContext("/static", new StaticFileHandler());
        
        // Health check для Render.com
        server.createContext("/health", new HealthCheckHandler());
        
        // Корневой путь - редирект на админ-панель
        server.createContext("/", new RootHandler());
    }
    
    public void start() {
        server.start();
        
        // Получаем внешний URL для Render.com
        String externalUrl = System.getenv().getOrDefault("RENDER_EXTERNAL_URL", "http://localhost:" + port);
        
        System.out.println("=== HomeCloud Admin Server Started ===");
        System.out.println("Local port: " + port);
        System.out.println("Bind address: " + System.getenv().getOrDefault("BIND_ADDRESS", "0.0.0.0"));
        System.out.println("Admin panel: " + externalUrl + "/admin");
        System.out.println("Health check: " + externalUrl + "/health");
        System.out.println("=====================================");
    }
    
    public void stop() {
        server.stop(0);
        System.out.println("Admin HTTP server stopped");
    }
    
    // Health check для Render.com
    private static class HealthCheckHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String response = """
                    {
                        "status": "healthy",
                        "service": "HomeCloud Admin Server",
                        "timestamp": "%s",
                        "version": "1.0.0"
                    }
                    """.formatted(java.time.Instant.now());
                
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.getBytes().length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    
    // Обработчик главной страницы админ-панели
    private static class AdminPanelHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    // Читаем HTML файл
                    String htmlContent = new String(Files.readAllBytes(
                        Paths.get("src/main/resources/admin_panel.html")
                    ));
                    
                    // Отправляем ответ
                    exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
                    exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                    exchange.sendResponseHeaders(200, htmlContent.getBytes().length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(htmlContent.getBytes());
                    }
                } catch (Exception e) {
                    // Если файл не найден, отправляем встроенный HTML
                    String fallbackHtml = getFallbackHtml();
                    exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
                    exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                    exchange.sendResponseHeaders(200, fallbackHtml.getBytes().length);
                    
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(fallbackHtml.getBytes());
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
        
        private String getFallbackHtml() {
            return """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>HomeCloud Admin Panel</title>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        h1 { color: #667eea; text-align: center; }
                        .status { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
                        .info { background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 5px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🏠 HomeCloud Server Admin Panel</h1>
                        <div class="status">
                            <strong>✅ Server Status:</strong> Running on Render.com
                        </div>
                        <div class="info">
                            <strong>ℹ️ Information:</strong><br>
                            • Admin panel is operational<br>
                            • Server is ready to accept connections<br>
                            • WebSocket server is running<br>
                            • Health check endpoint: /health
                        </div>
                        <div class="info">
                            <strong>🔧 Environment:</strong><br>
                            • Platform: Render.com<br>
                            • Java Version: %s<br>
                            • Server Time: %s
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(
                    System.getProperty("java.version"),
                    java.time.LocalDateTime.now()
                );
        }
    }
    
    // Обработчик API статистики
    private static class StatsApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                // Здесь можно получить реальную статистику от основного сервера
                String statsJson = """
                    {
                        "activeConnections": 0,
                        "totalRequests": 0,
                        "totalBytes": 0,
                        "uptime": 0,
                        "environment": "render.com",
                        "timestamp": "%s"
                    }
                    """.formatted(java.time.Instant.now());
                
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, statsJson.getBytes().length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(statsJson.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    
    // Обработчик API клиентов
    private static class ClientsApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String clientsJson = """
                    {
                        "clients": [],
                        "totalClients": 0,
                        "environment": "render.com",
                        "timestamp": "%s"
                    }
                    """.formatted(java.time.Instant.now());
                
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, clientsJson.getBytes().length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(clientsJson.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    
    // Обработчик API логов
    private static class LogsApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String logsJson = """
                    {
                        "logs": [
                            "Server started successfully on Render.com",
                            "Admin panel HTTP server running",
                            "Health check endpoint available at /health",
                            "WebSocket server ready for connections",
                            "Environment: %s"
                        ],
                        "environment": "render.com",
                        "timestamp": "%s"
                    }
                    """.formatted(
                        System.getenv().getOrDefault("RENDER_ENVIRONMENT", "production"),
                        java.time.Instant.now()
                    );
                
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, logsJson.getBytes().length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(logsJson.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    
    // Обработчик статических файлов
    private static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String contentType = getContentType(path);
            
            try {
                byte[] content = Files.readAllBytes(Paths.get("src/main/resources" + path));
                
                exchange.getResponseHeaders().add("Content-Type", contentType);
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, content.length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(content);
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(404, -1); // File not found
            }
        }
        
        private String getContentType(String path) {
            if (path.endsWith(".css")) return "text/css";
            if (path.endsWith(".js")) return "application/javascript";
            if (path.endsWith(".png")) return "image/png";
            if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
            if (path.endsWith(".gif")) return "image/gif";
            return "text/plain";
        }
    }
    
    // Обработчик корневого пути
    private static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Редирект на админ-панель
            exchange.getResponseHeaders().add("Location", "/admin");
            exchange.sendResponseHeaders(302, -1); // Found (Redirect)
        }
    }
}
