package org.example.managers;

import io.netty.channel.Channel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages client connections and pairing
 */
public class ClientManager {
    
    private static final Map<String, String> tokenPairs = new ConcurrentHashMap<>();
    private static final Map<String, Channel> clients = new ConcurrentHashMap<>();
    
    /**
     * Register a new client
     */
    public static void registerClient(String userId, Channel channel) {
        clients.put(userId, channel);
        System.out.println("[CLIENT_MANAGER] Client registered: " + userId);
    }
    
    /**
     * Unregister a client
     */
    public static void unregisterClient(String userId) {
        clients.remove(userId);
        // Remove from pairs
        String pairUserId = tokenPairs.remove(userId);
        if (pairUserId != null) {
            tokenPairs.remove(pairUserId);
            System.out.println("[CLIENT_MANAGER] Pair removed for: " + userId + " and " + pairUserId);
        }
        System.out.println("[CLIENT_MANAGER] Client unregistered: " + userId);
    }
    
    /**
     * Get client channel by userId
     */
    public static Channel getClient(String userId) {
        return clients.get(userId);
    }
    
    /**
     * Check if client is connected
     */
    public static boolean isClientConnected(String userId) {
        Channel channel = clients.get(userId);
        return channel != null && channel.isActive();
    }
    
    /**
     * Get all connected clients
     */
    public static Map<String, Channel> getAllClients() {
        return new ConcurrentHashMap<>(clients);
    }
    
    /**
     * Get total client count
     */
    public static int getClientCount() {
        return clients.size();
    }
    
    /**
     * Register a pair between Android and PC clients
     */
    public static void registerPair(String androidUserId, String pcUserId) {
        tokenPairs.put(pcUserId, androidUserId);
        tokenPairs.put(androidUserId, pcUserId);
        System.out.println("[CLIENT_MANAGER] Pair registered: Android=" + androidUserId + ", PC=" + pcUserId);
    }
    
    /**
     * Get paired client userId
     */
    public static String getPairedClient(String userId) {
        return tokenPairs.get(userId);
    }
    
    /**
     * Check if client has a pair
     */
    public static boolean hasPair(String userId) {
        return tokenPairs.containsKey(userId);
    }
    
    /**
     * Remove pairing for a client
     */
    public static void removePair(String userId) {
        String pairUserId = tokenPairs.remove(userId);
        if (pairUserId != null) {
            tokenPairs.remove(pairUserId);
            System.out.println("[CLIENT_MANAGER] Pair removed for: " + userId + " and " + pairUserId);
        }
    }
    
    /**
     * Get all pairs
     */
    public static Map<String, String> getAllPairs() {
        return new ConcurrentHashMap<>(tokenPairs);
    }
}
