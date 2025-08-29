package org.example;

import org.json.JSONObject;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Queue;

/**
 * Manages server statistics and metrics
 */
public class ServerStatistics {
    private static final long startTime = System.currentTimeMillis();
    private static final AtomicLong totalFileTransfers = new AtomicLong(0);
    private static final AtomicLong totalBytesTransferred = new AtomicLong(0);
    private static final AtomicLong activeConnections = new AtomicLong(0);
    
    // File transfer tracking
    private static final Map<String, Long> fileTransferSize = new ConcurrentHashMap<>();
    private static final Map<String, Long> activeFileStreams = new ConcurrentHashMap<>();
    
    /**
     * Increment file transfer count
     */
    public static void incrementFileTransfers() {
        totalFileTransfers.incrementAndGet();
    }
    
    /**
     * Add bytes transferred
     */
    public static void addBytesTransferred(long bytes) {
        totalBytesTransferred.addAndGet(bytes);
    }
    
    /**
     * Set active connections count
     */
    public static void setActiveConnections(int count) {
        activeConnections.set(count);
    }
    
    /**
     * Add active file stream
     */
    public static void addActiveFileStream(String transferId, long fileSize) {
        activeFileStreams.put(transferId, fileSize);
        fileTransferSize.put(transferId, fileSize);
    }
    
    /**
     * Remove active file stream
     */
    public static void removeActiveFileStream(String transferId) {
        activeFileStreams.remove(transferId);
    }
    
    /**
     * Get server statistics as JSON
     */
    public static JSONObject getStatistics() {
        JSONObject stats = new JSONObject();
        
        // Basic stats
        stats.put("totalClients", activeConnections.get());
        stats.put("activeTransfers", activeFileStreams.size());
        stats.put("serverUptime", System.currentTimeMillis() - startTime);
        stats.put("totalFileTransfers", totalFileTransfers.get());
        stats.put("totalBytesTransferred", totalBytesTransferred.get());
        
        // Memory usage
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        stats.put("memoryUsed", usedMemory);
        stats.put("memoryTotal", totalMemory);
        stats.put("memoryFree", freeMemory);
        
        return stats;
    }
    
    /**
     * Get server uptime in milliseconds
     */
    public static long getUptime() {
        return System.currentTimeMillis() - startTime;
    }
    
    /**
     * Get total file transfers count
     */
    public static long getTotalFileTransfers() {
        return totalFileTransfers.get();
    }
    
    /**
     * Get active file streams count
     */
    public static int getActiveFileStreamsCount() {
        return activeFileStreams.size();
    }
}
