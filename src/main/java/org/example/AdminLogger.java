package org.example;

import java.util.Queue;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * Centralized logging and admin session management system
 * Replaces System.out logging with in-memory log storage
 */
public class AdminLogger {
    private static final Queue<LogEntry> serverLogs = new LinkedList<>();
    private static final int MAX_LOGS = 1000;
    private static final Map<String, AdminSession> adminSessions = new ConcurrentHashMap<>();
    private static final long SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
    
    // Admin credentials (can be configured via environment variables)
    public static final String ADMIN_USERNAME = System.getenv().getOrDefault("ADMIN_USERNAME", "admin");
    public static final String ADMIN_PASSWORD = System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123");
    
    // Log levels
    public static final String INFO = "INFO";
    public static final String WARN = "WARN";
    public static final String ERROR = "ERROR";
    public static final String SECURITY = "SECURITY";
    public static final String ADMIN = "ADMIN";
    
    /**
     * Log entry class
     */
    public static class LogEntry {
        public final long timestamp;
        public final String level;
        public final String source;
        public final String message;
        public final String formattedTime;
        
        public LogEntry(String level, String source, String message) {
            this.timestamp = System.currentTimeMillis();
            this.level = level;
            this.source = source;
            this.message = message;
            this.formattedTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(timestamp));
        }
        
        public JSONObject toJSON() {
            JSONObject json = new JSONObject();
            json.put("timestamp", timestamp);
            json.put("time", formattedTime);
            json.put("level", level);
            json.put("source", source);
            json.put("message", message);
            return json;
        }
        
        @Override
        public String toString() {
            return String.format("[%s] %-8s [%-12s] %s", formattedTime, level, source, message);
        }
    }
    
    /**
     * Admin session class
     */
    public static class AdminSession {
        public final String username;
        public final long createdAt;
        public long lastActivity;
        
        public AdminSession(String username) {
            this.username = username;
            this.createdAt = System.currentTimeMillis();
            this.lastActivity = createdAt;
        }
        
        public boolean isExpired() {
            return (System.currentTimeMillis() - lastActivity) > SESSION_TIMEOUT;
        }
        
        public void updateActivity() {
            this.lastActivity = System.currentTimeMillis();
        }
    }
    
    /**
     * Centralized logging method - replaces System.out.println
     */
    public static void log(String level, String source, String message) {
        LogEntry entry = new LogEntry(level, source, message);
        
        synchronized (serverLogs) {
            serverLogs.offer(entry);
            if (serverLogs.size() > MAX_LOGS) {
                serverLogs.poll();
            }
        }
        
        // Print to console by default (can be disabled with CONSOLE_LOGGING=false)
        boolean CONSOLE_LOGGING = Boolean.parseBoolean(System.getenv().getOrDefault("CONSOLE_LOGGING", "true"));
        if (CONSOLE_LOGGING) {
            System.out.println(entry.toString());
        }
    }
    
    // Convenience logging methods
    public static void info(String source, String message) {
        log(INFO, source, message);
    }
    
    public static void warn(String source, String message) {
        log(WARN, source, message);
    }
    
    public static void error(String source, String message) {
        log(ERROR, source, message);
    }
    
    public static void security(String source, String message) {
        log(SECURITY, source, message);
    }
    
    public static void admin(String source, String message) {
        log(ADMIN, source, message);
    }
    
    /**
     * Gets all server logs as List
     */
    public static List<LogEntry> getLogs() {
        synchronized (serverLogs) {
            return new ArrayList<>(serverLogs);
        }
    }
    
    /**
     * Gets filtered logs
     */
    public static List<LogEntry> getFilteredLogs(String level, String search) {
        synchronized (serverLogs) {
            List<LogEntry> filtered = new ArrayList<>();
            for (LogEntry entry : serverLogs) {
                boolean levelMatch = level == null || level.isEmpty() || level.equals("ALL") || entry.level.equals(level);
                boolean searchMatch = search == null || search.isEmpty() || 
                    entry.message.toLowerCase().contains(search.toLowerCase()) ||
                    entry.source.toLowerCase().contains(search.toLowerCase());
                
                if (levelMatch && searchMatch) {
                    filtered.add(entry);
                }
            }
            return filtered;
        }
    }
    
    /**
     * Gets logs as JSON array
     */
    public static JSONArray getLogsJSON() {
        return getLogsJSON(null, null);
    }
    
    public static JSONArray getLogsJSON(String level, String search) {
        List<LogEntry> logs = getFilteredLogs(level, search);
        JSONArray array = new JSONArray();
        for (LogEntry entry : logs) {
            array.put(entry.toJSON());
        }
        return array;
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
     * Clear all logs
     */
    public static void clearLogs() {
        synchronized (serverLogs) {
            serverLogs.clear();
        }
        admin("LOGGER", "All logs cleared");
    }
    
    /**
     * Creates admin session
     */
    public static String createSession(String username) {
        // Clean expired sessions
        cleanExpiredSessions();
        
        String sessionToken = java.util.UUID.randomUUID().toString();
        adminSessions.put(sessionToken, new AdminSession(username));
        admin("AUTH", "Admin session created: " + username);
        return sessionToken;
    }
    
    /**
     * Validates and updates admin session
     */
    public static boolean isValidSession(String sessionToken) {
        if (sessionToken == null || sessionToken.isEmpty()) {
            return false;
        }
        
        AdminSession session = adminSessions.get(sessionToken);
        if (session == null) {
            return false;
        }
        
        if (session.isExpired()) {
            adminSessions.remove(sessionToken);
            admin("AUTH", "Session expired: " + session.username);
            return false;
        }
        
        session.updateActivity();
        return true;
    }
    
    /**
     * Get session username
     */
    public static String getSessionUsername(String sessionToken) {
        AdminSession session = adminSessions.get(sessionToken);
        return session != null ? session.username : null;
    }
    
    /**
     * Removes admin session (logout)
     */
    public static void removeSession(String sessionToken) {
        AdminSession session = adminSessions.remove(sessionToken);
        if (session != null) {
            admin("AUTH", "Admin logged out: " + session.username);
        }
    }
    
    /**
     * Clean expired sessions
     */
    private static void cleanExpiredSessions() {
        adminSessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
    
    /**
     * Validates admin credentials
     */
    public static boolean validateCredentials(String username, String password) {
        boolean valid = ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password);
        if (valid) {
            admin("AUTH", "Admin login successful: " + username);
        } else {
            warn("AUTH", "Failed login attempt for user: " + username);
        }
        return valid;
    }
    
    /**
     * Get active sessions count
     */
    public static int getActiveSessionsCount() {
        cleanExpiredSessions();
        return adminSessions.size();
    }
}
