package org.example.admin;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.json.JSONObject;
import org.json.JSONArray;
import org.example.AdminLogger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages client pairs and provides admin operations
 */
public class PairManager {
    
    /**
     * Information about a paired connection
     */
    public static class PairInfo {
        public final String pcUserId;
        public final String androidUserId;
        public final long pairedAt;
        public long lastActivity;
        public int filesTransferred;
        public long bytesTransferred;
        
        public PairInfo(String pcUserId, String androidUserId) {
            this.pcUserId = pcUserId;
            this.androidUserId = androidUserId;
            this.pairedAt = System.currentTimeMillis();
            this.lastActivity = pairedAt;
            this.filesTransferred = 0;
            this.bytesTransferred = 0;
        }
        
        public void updateActivity() {
            this.lastActivity = System.currentTimeMillis();
        }
        
        public boolean isActive(Map<String, Channel> clients) {
            Channel pcChannel = clients.get(pcUserId);
            Channel androidChannel = clients.get(androidUserId);
            return (pcChannel != null && pcChannel.isActive()) || 
                   (androidChannel != null && androidChannel.isActive());
        }
        
        public boolean isBothOnline(Map<String, Channel> clients) {
            Channel pcChannel = clients.get(pcUserId);
            Channel androidChannel = clients.get(androidUserId);
            return (pcChannel != null && pcChannel.isActive()) && 
                   (androidChannel != null && androidChannel.isActive());
        }
        
        public String getStatus(Map<String, Channel> clients) {
            if (isBothOnline(clients)) {
                return "ONLINE";
            } else if (isActive(clients)) {
                return "PARTIAL";
            } else {
                return "OFFLINE";
            }
        }
        
        public long getUptime() {
            return System.currentTimeMillis() - pairedAt;
        }
        
        public long getInactiveTime() {
            return System.currentTimeMillis() - lastActivity;
        }
        
        public JSONObject toJSON(Map<String, Channel> clients) {
            JSONObject json = new JSONObject();
            json.put("pcUserId", pcUserId);
            json.put("androidUserId", androidUserId);
            json.put("pairedAt", pairedAt);
            json.put("lastActivity", lastActivity);
            json.put("uptime", getUptime());
            json.put("inactiveTime", getInactiveTime());
            json.put("filesTransferred", filesTransferred);
            json.put("bytesTransferred", bytesTransferred);
            json.put("status", getStatus(clients));
            json.put("bothOnline", isBothOnline(clients));
            
            // Client connection details
            Channel pcChannel = clients.get(pcUserId);
            Channel androidChannel = clients.get(androidUserId);
            
            json.put("pcOnline", pcChannel != null && pcChannel.isActive());
            json.put("androidOnline", androidChannel != null && androidChannel.isActive());
            
            if (pcChannel != null) {
                json.put("pcAddress", pcChannel.remoteAddress().toString());
            }
            if (androidChannel != null) {
                json.put("androidAddress", androidChannel.remoteAddress().toString());
            }
            
            return json;
        }
    }
    
    // Track pair information
    private static final Map<String, PairInfo> pairInfoMap = new ConcurrentHashMap<>();
    
    /**
     * Register a new pair
     */
    public static void registerPair(String pcUserId, String androidUserId) {
        String pairKey = getPairKey(pcUserId, androidUserId);
        pairInfoMap.put(pairKey, new PairInfo(pcUserId, androidUserId));
        AdminLogger.info("PAIR_MGR", "Pair registered: PC=" + pcUserId + " <-> Android=" + androidUserId);
    }
    
    /**
     * Unregister a pair
     */
    public static void unregisterPair(String pcUserId, String androidUserId) {
        String pairKey = getPairKey(pcUserId, androidUserId);
        pairInfoMap.remove(pairKey);
        AdminLogger.info("PAIR_MGR", "Pair unregistered: PC=" + pcUserId + " <-> Android=" + androidUserId);
    }
    
    /**
     * Update pair activity
     */
    public static void updatePairActivity(String userId1, String userId2) {
        String pairKey = getPairKey(userId1, userId2);
        PairInfo info = pairInfoMap.get(pairKey);
        if (info != null) {
            info.updateActivity();
        }
    }
    
    /**
     * Record file transfer
     */
    public static void recordFileTransfer(String userId1, String userId2, long bytes) {
        String pairKey = getPairKey(userId1, userId2);
        PairInfo info = pairInfoMap.get(pairKey);
        if (info != null) {
            info.filesTransferred++;
            info.bytesTransferred += bytes;
            info.updateActivity();
        }
    }
    
    /**
     * Get all pairs
     */
    public static List<PairInfo> getAllPairs() {
        return new ArrayList<>(pairInfoMap.values());
    }
    
    /**
     * Get all pairs as JSON
     */
    public static JSONArray getAllPairsJSON(Map<String, Channel> clients) {
        JSONArray array = new JSONArray();
        for (PairInfo pair : pairInfoMap.values()) {
            array.put(pair.toJSON(clients));
        }
        return array;
    }
    
    /**
     * Get active pairs count
     */
    public static int getActivePairsCount(Map<String, Channel> clients) {
        int count = 0;
        for (PairInfo pair : pairInfoMap.values()) {
            if (pair.isActive(clients)) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Get offline pairs count
     */
    public static int getOfflinePairsCount(Map<String, Channel> clients) {
        int count = 0;
        for (PairInfo pair : pairInfoMap.values()) {
            if (!pair.isActive(clients)) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Delete a specific pair
     */
    public static boolean deletePair(String pcUserId, String androidUserId, 
                                     Map<String, String> tokenPairs, 
                                     Map<String, Channel> clients,
                                     Runnable savePairingsCallback) {
        String pairKey = getPairKey(pcUserId, androidUserId);
        PairInfo info = pairInfoMap.remove(pairKey);
        
        if (info != null) {
            // Remove from tokenPairs
            tokenPairs.remove(pcUserId);
            tokenPairs.remove(androidUserId);
            
            // Save pairings to file
            if (savePairingsCallback != null) {
                savePairingsCallback.run();
            }
            
            // Notify clients
            Channel pcChannel = clients.get(pcUserId);
            Channel androidChannel = clients.get(androidUserId);
            
            if (pcChannel != null && pcChannel.isActive()) {
                pcChannel.writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:" + androidUserId));
                pcChannel.writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
            }
            
            if (androidChannel != null && androidChannel.isActive()) {
                androidChannel.writeAndFlush(new TextWebSocketFrame("PAIR_DELETED:" + pcUserId));
                androidChannel.writeAndFlush(new TextWebSocketFrame("PAIR_STATUS:NO"));
            }
            
            AdminLogger.admin("PAIR_MGR", "Pair deleted by admin: PC=" + pcUserId + " <-> Android=" + androidUserId);
            return true;
        }
        
        return false;
    }
    
    /**
     * Delete all pairs
     */
    public static int deleteAllPairs(Map<String, String> tokenPairs, 
                                     Map<String, Channel> clients,
                                     Runnable savePairingsCallback) {
        int count = 0;
        List<PairInfo> allPairs = new ArrayList<>(pairInfoMap.values());
        
        for (PairInfo pair : allPairs) {
            if (deletePair(pair.pcUserId, pair.androidUserId, tokenPairs, clients, savePairingsCallback)) {
                count++;
            }
        }
        
        AdminLogger.admin("PAIR_MGR", "All pairs deleted by admin: " + count + " pairs");
        return count;
    }
    
    /**
     * Disconnect a client
     */
    public static boolean disconnectClient(String userId, Map<String, Channel> clients) {
        Channel channel = clients.get(userId);
        if (channel != null && channel.isActive()) {
            channel.writeAndFlush(new TextWebSocketFrame("SERVER_DISCONNECT:Admin requested disconnect"));
            channel.close();
            AdminLogger.admin("CLIENT_MGR", "Client disconnected by admin: " + userId);
            return true;
        }
        return false;
    }
    
    /**
     * Disconnect both clients in a pair
     */
    public static int disconnectPair(String pcUserId, String androidUserId, Map<String, Channel> clients) {
        int count = 0;
        if (disconnectClient(pcUserId, clients)) count++;
        if (disconnectClient(androidUserId, clients)) count++;
        return count;
    }
    
    /**
     * Get pair key (order-independent)
     */
    private static String getPairKey(String userId1, String userId2) {
        // Always use same order for consistency
        if (userId1.compareTo(userId2) < 0) {
            return userId1 + ":" + userId2;
        } else {
            return userId2 + ":" + userId1;
        }
    }
    
    /**
     * Get statistics
     */
    public static JSONObject getStatistics(Map<String, Channel> clients) {
        JSONObject stats = new JSONObject();
        
        int totalPairs = pairInfoMap.size();
        int activePairs = getActivePairsCount(clients);
        int offlinePairs = getOfflinePairsCount(clients);
        
        long totalFiles = 0;
        long totalBytes = 0;
        
        for (PairInfo pair : pairInfoMap.values()) {
            totalFiles += pair.filesTransferred;
            totalBytes += pair.bytesTransferred;
        }
        
        stats.put("totalPairs", totalPairs);
        stats.put("activePairs", activePairs);
        stats.put("offlinePairs", offlinePairs);
        stats.put("totalFilesTransferred", totalFiles);
        stats.put("totalBytesTransferred", totalBytes);
        
        return stats;
    }
}

