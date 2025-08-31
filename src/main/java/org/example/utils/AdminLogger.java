package org.example.utils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Queue;
import java.util.LinkedList;

/**
 * Admin logging utility
 */
public class AdminLogger {
    
    private static final Queue<String> serverLogs = new LinkedList<>();
    private static final int MAX_LOGS = ServerConfig.MAX_LOGS;
    
    /**
     * Log an admin event
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
     * Get all logs
     */
    public static Queue<String> getLogs() {
        synchronized (serverLogs) {
            return new LinkedList<>(serverLogs);
        }
    }
    
    /**
     * Clear all logs
     */
    public static void clearLogs() {
        synchronized (serverLogs) {
            serverLogs.clear();
        }
    }
}
