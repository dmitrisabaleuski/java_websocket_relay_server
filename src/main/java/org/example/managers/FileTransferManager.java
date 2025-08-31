package org.example.managers;

import org.example.utils.ServerConfig;
import java.io.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages file transfers between clients
 */
public class FileTransferManager {
    
    private static final Map<String, Long> fileTransferSize = new ConcurrentHashMap<>();
    private static final Map<String, Long> fileExpectedSize = new ConcurrentHashMap<>();
    private static final Map<String, OutputStream> activeFileStreams = new ConcurrentHashMap<>();
    private static final Map<String, String> activeFileNames = new ConcurrentHashMap<>();
    
    /**
     * Start a new file transfer
     */
    public static boolean startFileTransfer(String transferId, String filename, long expectedSize) {
        if (activeFileStreams.size() >= ServerConfig.MAX_ACTIVE_TRANSFERS) {
            System.err.println("[FILE_MANAGER] BUSY:MAX_TRANSFERS for transferId=" + transferId);
            return false;
        }
        
        try {
            File uploadsDir = new File(ServerConfig.UPLOADS_DIR);
            if (!uploadsDir.exists()) uploadsDir.mkdirs();
            
            OutputStream fos = new FileOutputStream(new File(uploadsDir, filename));
            activeFileStreams.put(transferId, fos);
            activeFileNames.put(transferId, filename);
            fileTransferSize.put(transferId, 0L);
            fileExpectedSize.put(transferId, expectedSize);
            
            System.out.println("[FILE_MANAGER] File transfer started: " + filename + " (transferId=" + transferId + ")");
            return true;
        } catch (Exception e) {
            System.err.println("[FILE_MANAGER] Failed to start file transfer: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Write file data chunk
     */
    public static boolean writeFileChunk(String transferId, byte[] chunk) {
        OutputStream fos = activeFileStreams.get(transferId);
        if (fos == null) {
            System.err.println("[FILE_MANAGER] No file stream for transferId: " + transferId);
            return false;
        }
        
        try {
            fos.write(chunk);
            long totalReceived = fileTransferSize.getOrDefault(transferId, 0L) + chunk.length;
            fileTransferSize.put(transferId, totalReceived);
            
            System.out.println("[FILE_MANAGER] File chunk written: transferId=" + transferId + 
                             ", chunkSize=" + chunk.length + ", totalReceived=" + totalReceived);
            return true;
        } catch (IOException e) {
            System.err.println("[FILE_MANAGER] File write error: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Complete file transfer
     */
    public static boolean completeFileTransfer(String transferId) {
        OutputStream fos = activeFileStreams.remove(transferId);
        String fileName = activeFileNames.remove(transferId);
        
        if (fos != null) {
            try {
                fos.close();
                System.out.println("[FILE_MANAGER] File transfer completed: " + fileName + " (transferId=" + transferId + ")");
            } catch (Exception e) {
                System.err.println("[FILE_MANAGER] Error closing file: " + e.getMessage());
            }
        }
        
        fileTransferSize.remove(transferId);
        fileExpectedSize.remove(transferId);
        
        return true;
    }
    
    /**
     * Get active transfer count
     */
    public static int getActiveTransferCount() {
        return activeFileStreams.size();
    }
    
    /**
     * Get total transfer count
     */
    public static int getTotalTransferCount() {
        return fileTransferSize.size();
    }
    
    /**
     * Check if transfer is active
     */
    public static boolean isTransferActive(String transferId) {
        return activeFileStreams.containsKey(transferId);
    }
    
    /**
     * Get transfer progress
     */
    public static double getTransferProgress(String transferId) {
        Long received = fileTransferSize.get(transferId);
        Long expected = fileExpectedSize.get(transferId);
        
        if (received == null || expected == null || expected == 0) {
            return 0.0;
        }
        
        return (double) received / expected * 100.0;
    }
    
    /**
     * Clean up all active transfers
     */
    public static void cleanupAllTransfers() {
        for (Map.Entry<String, OutputStream> entry : activeFileStreams.entrySet()) {
            try {
                entry.getValue().close();
            } catch (Exception e) {
                System.err.println("[FILE_MANAGER] Error closing file stream: " + e.getMessage());
            }
        }
        
        activeFileStreams.clear();
        activeFileNames.clear();
        fileTransferSize.clear();
        fileExpectedSize.clear();
        
        System.out.println("[FILE_MANAGER] All file transfers cleaned up");
    }
}
