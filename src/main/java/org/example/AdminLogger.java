package org.example;

import java.util.Queue;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * Manages admin logging and session management
 */
public class AdminLogger {
    private static final Queue<String> serverLogs = new LinkedList<>();
    private static final int MAX_LOGS = 1000;
    private static final Map<String, String> adminSessions = new ConcurrentHashMap<>();
    
    // Admin credentials (can be configured via environment variables)
    public static final String ADMIN_USERNAME = System.getenv().getOrDefault("ADMIN_USERNAME", "admin");
    public static final String ADMIN_PASSWORD = System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123");
    
    /**
     * Logs admin events to the server logs
     */
    public static void log(String level, String source, String message) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String logEntry = String.format("[%s] %s [%s] %s", timestamp, level, source, message);
        
        synchronized (serverLogs) {
            serverLogs.offer(logEntry);
            if (serverLogs.size() > MAX_LOGS) {
                serverLogs.poll();
            }
        }
        
        System.out.println(logEntry);
    }
    
    /**
     * Gets all server logs
     */
    public static Queue<String> getLogs() {
        synchronized (serverLogs) {
            return new LinkedList<>(serverLogs);
        }
    }
    
    /**
     * Gets logs count
     */
    public static int getLogsCount() {
        synchronized (serverLogs) {
            return serverLogs.size();
        }
    }
    
    /**
     * Creates admin session
     */
    public static String createSession(String username) {
        String sessionToken = java.util.UUID.randomUUID().toString();
        adminSessions.put(sessionToken, username);
        return sessionToken;
    }
    
    /**
     * Validates admin session
     */
    public static boolean isValidSession(String sessionToken) {
        return adminSessions.containsKey(sessionToken);
    }
    
    /**
     * Removes admin session
     */
    public static void removeSession(String sessionToken) {
        adminSessions.remove(sessionToken);
    }
    
    /**
     * Validates admin credentials
     */
    public static boolean validateCredentials(String username, String password) {
        return ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password);
    }
}
