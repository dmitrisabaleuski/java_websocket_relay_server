package org.example.utils;

/**
 * Server configuration constants
 */
public class ServerConfig {
    
    public static final String SECRET = System.getenv().getOrDefault("JWT_SECRET", "eY9xh9F!j$3Kz0@VqLu7pT1cG2mNwqAr");
    public static final String UPLOADS_DIR = System.getenv().getOrDefault("UPLOADS_DIR", "uploads");
    public static final int MAX_ACTIVE_TRANSFERS = 20;
    public static final long HEARTBEAT_INTERVAL = 30000; // 30 seconds
    public static final String ADMIN_USERNAME = System.getenv().getOrDefault("ADMIN_USERNAME", "admin");
    public static final String ADMIN_PASSWORD = System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123");
    public static final int MAX_LOGS = 1000;
}
