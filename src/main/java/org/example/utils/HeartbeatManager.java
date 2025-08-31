package org.example.utils;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.example.managers.ClientManager;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Manages heartbeat system for connected clients
 */
public class HeartbeatManager {
    
    private static final Timer heartbeatTimer = new Timer(true);
    private static final long HEARTBEAT_INTERVAL = ServerConfig.HEARTBEAT_INTERVAL;
    
    /**
     * Start heartbeat timer
     */
    public static void startHeartbeatTimer() {
        heartbeatTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    sendHeartbeatToAllClients();
                } catch (Exception e) {
                    System.err.println("[HEARTBEAT] Error sending heartbeat: " + e.getMessage());
                }
            }
        }, HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
        
        System.out.println("[HEARTBEAT] Heartbeat timer started with interval: " + HEARTBEAT_INTERVAL + "ms");
    }
    
    /**
     * Stop heartbeat timer
     */
    public static void stopHeartbeatTimer() {
        if (heartbeatTimer != null) {
            heartbeatTimer.cancel();
            System.out.println("[HEARTBEAT] Heartbeat timer stopped");
        }
    }
    
    /**
     * Send PING to all connected clients
     */
    private static void sendHeartbeatToAllClients() {
        Map<String, Channel> clients = ClientManager.getAllClients();
        
        if (clients.isEmpty()) {
            return;
        }
        
        System.out.println("[HEARTBEAT] Sending PING to " + clients.size() + " connected clients");
        
        for (Map.Entry<String, Channel> entry : clients.entrySet()) {
            Channel channel = entry.getValue();
            String userId = entry.getKey();
            
            if (channel != null && channel.isActive()) {
                try {
                    channel.writeAndFlush(new TextWebSocketFrame("PING"));
                    System.out.println("[HEARTBEAT] Sent PING to userId: " + userId);
                } catch (Exception e) {
                    System.err.println("[HEARTBEAT] Failed to send PING to userId " + userId + ": " + e.getMessage());
                    // Remove inactive channel
                    ClientManager.unregisterClient(userId);
                    System.out.println("[HEARTBEAT] Removed inactive channel for userId: " + userId);
                }
            } else {
                // Remove inactive channel
                ClientManager.unregisterClient(userId);
                System.out.println("[HEARTBEAT] Removed inactive channel for userId: " + userId);
            }
        }
    }
}
