package org.example;

import java.text.SimpleDateFormat;
import java.util.*;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * Detailed audit logging for compliance and security tracking
 * Logs file transfers with full context: user, file name, size, IP, timestamps, success/failure
 */
public class AuditLogger {
    private static final Queue<AuditEntry> auditLogs = new LinkedList<>();
    private static final int MAX_AUDIT_LOGS = 10000; // Keep more audit logs than regular logs
    private static final boolean AUDIT_ENABLED = Boolean.parseBoolean(
        System.getenv().getOrDefault("AUDIT_ENABLED", "true")
    );
    
    /**
     * Audit entry class with detailed information
     */
    public static class AuditEntry {
        public final String timestamp;
        public final String user;
        public final String action;
        public final String fileName;
        public final long fileSize;
        public final String from;
        public final String to;
        public final String ip;
        public final boolean success;
        public final String details;
        
        public AuditEntry(String user, String action, String fileName, long fileSize,
                         String from, String to, String ip, boolean success, String details) {
            this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            this.user = user;
            this.action = action;
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.from = from;
            this.to = to;
            this.ip = ip;
            this.success = success;
            this.details = details;
        }
        
        public JSONObject toJSON() {
            JSONObject json = new JSONObject();
            json.put("timestamp", timestamp);
            json.put("user", user);
            json.put("action", action);
            json.put("fileName", fileName);
            json.put("fileSize", fileSize);
            json.put("from", from);
            json.put("to", to);
            json.put("ip", ip);
            json.put("success", success);
            json.put("details", details);
            return json;
        }
        
        public String toCSV() {
            return String.format("%s,%s,%s,%s,%d,%s,%s,%s,%b,%s",
                timestamp, user, action, fileName, fileSize, from, to, ip, success, details);
        }
        
        @Override
        public String toString() {
            return String.format("[%s] User=%s Action=%s File=%s Size=%d From=%s To=%s IP=%s Success=%b Details=%s",
                timestamp, user, action, fileName, fileSize, from, to, ip, success, details);
        }
    }
    
    /**
     * Log a file transfer event
     */
    public static void logFileTransfer(String userId, String fileName, long fileSize,
                                      String fromClient, String toClient, String clientIP,
                                      boolean success, String additionalDetails) {
        if (!AUDIT_ENABLED) return;
        
        AuditEntry entry = new AuditEntry(
            userId != null ? userId : "unknown",
            "FILE_TRANSFER",
            fileName != null ? fileName : "unknown",
            fileSize,
            fromClient != null ? fromClient : "unknown",
            toClient != null ? toClient : "unknown",
            clientIP != null ? clientIP : "unknown",
            success,
            additionalDetails != null ? additionalDetails : ""
        );
        
        synchronized (auditLogs) {
            auditLogs.offer(entry);
            if (auditLogs.size() > MAX_AUDIT_LOGS) {
                auditLogs.poll();
            }
        }
        
        // Also log to console for immediate visibility
        System.out.println("[AUDIT] " + entry.toString());
    }
    
    /**
     * Log file send event
     */
    public static void logFileSent(String userId, String fileName, long fileSize,
                                   String fromClient, String clientIP, boolean success) {
        logFileTransfer(userId, fileName, fileSize, fromClient, "paired_client", clientIP, success, "File sent");
    }
    
    /**
     * Log file received event
     */
    public static void logFileReceived(String userId, String fileName, long fileSize,
                                       String toClient, String clientIP, boolean success) {
        logFileTransfer(userId, fileName, fileSize, "paired_client", toClient, clientIP, success, "File received");
    }
    
    /**
     * Get all audit logs
     */
    public static List<AuditEntry> getAuditLogs() {
        synchronized (auditLogs) {
            return new ArrayList<>(auditLogs);
        }
    }
    
    /**
     * Get filtered audit logs
     */
    public static List<AuditEntry> getFilteredAuditLogs(String user, String action, 
                                                        String fileName, Long dateFrom, Long dateTo) {
        synchronized (auditLogs) {
            List<AuditEntry> filtered = new ArrayList<>();
            for (AuditEntry entry : auditLogs) {
                boolean userMatch = user == null || user.isEmpty() || entry.user.equals(user);
                boolean actionMatch = action == null || action.isEmpty() || entry.action.equals(action);
                boolean fileMatch = fileName == null || fileName.isEmpty() || entry.fileName.contains(fileName);
                // TODO: Add date filtering if needed
                
                if (userMatch && actionMatch && fileMatch) {
                    filtered.add(entry);
                }
            }
            return filtered;
        }
    }
    
    /**
     * Get audit logs as JSON array
     */
    public static JSONArray getAuditLogsJSON() {
        return getAuditLogsJSON(null, null, null);
    }
    
    public static JSONArray getAuditLogsJSON(String user, String action, String fileName) {
        List<AuditEntry> logs = getFilteredAuditLogs(user, action, fileName, null, null);
        JSONArray array = new JSONArray();
        for (AuditEntry entry : logs) {
            array.put(entry.toJSON());
        }
        return array;
    }
    
    /**
     * Export audit logs as CSV
     */
    public static String exportAsCSV(List<AuditEntry> entries) {
        StringBuilder csv = new StringBuilder();
        csv.append("timestamp,user,action,fileName,fileSize,from,to,ip,success,details\n");
        
        for (AuditEntry entry : entries) {
            csv.append(entry.toCSV()).append("\n");
        }
        
        return csv.toString();
    }
    
    /**
     * Clear all audit logs
     */
    public static void clearAuditLogs() {
        synchronized (auditLogs) {
            auditLogs.clear();
        }
        AdminLogger.admin("AUDIT", "All audit logs cleared");
    }
    
    /**
     * Get audit logs count
     */
    public static int getAuditLogsCount() {
        synchronized (auditLogs) {
            return auditLogs.size();
        }
    }
}

