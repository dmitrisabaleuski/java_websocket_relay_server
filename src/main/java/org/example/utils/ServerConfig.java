package org.example.utils;

import java.util.Map;

/**
 * Server configuration constants and settings
 */
public class ServerConfig {
    // Server settings
    public static final int DEFAULT_PORT = 8080;
    public static final String DEFAULT_UPLOADS_DIR = "uploads";
    public static final String DEFAULT_SECRET = "your-secret-key-change-this-in-production";
    
    // WebSocket settings
    public static final long HEARTBEAT_INTERVAL = 30000; // 30 seconds
    public static final int MAX_MESSAGE_SIZE = 65536; // 64KB
    
    // File transfer settings
    public static final int CHUNK_SIZE = 8192; // 8KB chunks
    public static final long MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB
    
    // Admin panel settings
    public static final String ADMIN_USERNAME = System.getenv().getOrDefault("ADMIN_USERNAME", "admin");
    public static final String ADMIN_PASSWORD = System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123");
    
    // Logging settings
    public static final int MAX_LOG_ENTRIES = 1000;
    
    /**
     * Get server port from environment or use default
     */
    public static int getPort() {
        return Integer.parseInt(System.getenv().getOrDefault("PORT", String.valueOf(DEFAULT_PORT)));
    }
    
    /**
     * Get uploads directory from environment or use default
     */
    public static String getUploadsDir() {
        return System.getenv().getOrDefault("UPLOADS_DIR", DEFAULT_UPLOADS_DIR);
    }
    
    /**
     * Get JWT secret from environment or use default
     */
    public static String getSecret() {
        return System.getenv().getOrDefault("JWT_SECRET", DEFAULT_SECRET);
    }
}
