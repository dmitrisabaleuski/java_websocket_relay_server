package org.example;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.example.AdminLogger;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Database Manager for PostgreSQL
 * Handles database initialization, connections, and data persistence
 */
public class DatabaseManager {
    private static HikariDataSource dataSource;
    private static final String TAG = "DatabaseManager";
    
    // Environment variables for database connection
    private static final String DB_URL = System.getenv().getOrDefault("DATABASE_URL", "");
    private static final String DB_USER = System.getenv().getOrDefault("DATABASE_USER", "postgres");
    private static final String DB_PASSWORD = System.getenv().getOrDefault("DATABASE_PASSWORD", "postgres");
    private static boolean isEnabled = false;
    
    /**
     * Check if database is enabled
     */
    public static boolean isEnabled() {
        return isEnabled && dataSource != null;
    }
    
    /**
     * Initialize database connection pool and create tables if they don't exist
     */
    public static synchronized void initialize() {
        if (dataSource != null) {
            AdminLogger.warn(TAG, "Database already initialized");
            return;
        }
        
        // Check if DATABASE_URL is set
        if (DB_URL == null || DB_URL.isEmpty()) {
            AdminLogger.info(TAG, "No DATABASE_URL set, database features disabled (using in-memory storage)");
            isEnabled = false;
            return;
        }
        
        isEnabled = true;
        
        try {
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(DB_URL);
            config.setUsername(DB_USER);
            config.setPassword(DB_PASSWORD);
            config.setMaximumPoolSize(10);
            config.setMinimumIdle(2);
            config.setConnectionTimeout(30000);
            config.setIdleTimeout(600000);
            config.setMaxLifetime(1800000);
            config.setLeakDetectionThreshold(60000);
            
            dataSource = new HikariDataSource(config);
            AdminLogger.info(TAG, "Database connection pool initialized");
            
            // Create tables if they don't exist
            createTablesIfNotExist();
            
        } catch (Exception e) {
            AdminLogger.error(TAG, "Failed to initialize database: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Create tables if they don't exist
     */
    private static void createTablesIfNotExist() {
        try (Connection conn = dataSource.getConnection()) {
            // Create pairs table
            String createPairsTable = """
                CREATE TABLE IF NOT EXISTS pairs (
                    id SERIAL PRIMARY KEY,
                    pc_user_id VARCHAR(255) NOT NULL,
                    android_user_id VARCHAR(255) NOT NULL,
                    shared_secret VARCHAR(500),
                    created_at TIMESTAMP DEFAULT NOW(),
                    last_activity TIMESTAMP DEFAULT NOW(),
                    UNIQUE(pc_user_id, android_user_id)
                );
                CREATE INDEX IF NOT EXISTS idx_pc_user ON pairs(pc_user_id);
                CREATE INDEX IF NOT EXISTS idx_android_user ON pairs(android_user_id);
            """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createPairsTable);
                AdminLogger.info(TAG, "Pairs table created/verified");
            }
            
            // Create file_transfers table
            String createFileTransfersTable = """
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id SERIAL PRIMARY KEY,
                    pc_user_id VARCHAR(255) NOT NULL,
                    android_user_id VARCHAR(255) NOT NULL,
                    file_name VARCHAR(500),
                    file_size BIGINT,
                    from_client VARCHAR(50),
                    to_client VARCHAR(50),
                    ip_address VARCHAR(50),
                    success BOOLEAN,
                    transfer_completed_at TIMESTAMP DEFAULT NOW(),
                    details TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_transfers_pc_user ON file_transfers(pc_user_id);
                CREATE INDEX IF NOT EXISTS idx_transfers_android_user ON file_transfers(android_user_id);
                CREATE INDEX IF NOT EXISTS idx_transfers_timestamp ON file_transfers(transfer_completed_at);
            """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createFileTransfersTable);
                AdminLogger.info(TAG, "File transfers table created/verified");
            }
            
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to create tables: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Register a pair (PC ↔ Android)
     */
    public static void registerPair(String pcUserId, String androidUserId, String sharedSecret) {
        if (!isEnabled || dataSource == null) {
            return; // Database disabled, skip
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = """
                INSERT INTO pairs (pc_user_id, android_user_id, shared_secret, created_at, last_activity)
                VALUES (?, ?, ?, NOW(), NOW())
                ON CONFLICT (pc_user_id, android_user_id)
                DO UPDATE SET shared_secret = EXCLUDED.shared_secret, last_activity = NOW()
            """;
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, pcUserId);
                stmt.setString(2, androidUserId);
                stmt.setString(3, sharedSecret);
                stmt.executeUpdate();
                AdminLogger.info(TAG, "Pair registered: PC=" + pcUserId + " ↔ Android=" + androidUserId);
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to register pair: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Get Android user ID for given PC user ID
     */
    public static String getAndroidUserId(String pcUserId) {
        if (!isEnabled || dataSource == null) {
            return null; // Database disabled, skip
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = "SELECT android_user_id FROM pairs WHERE pc_user_id = ?";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, pcUserId);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("android_user_id");
                    }
                }
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to get Android user ID: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * Get PC user ID for given Android user ID
     */
    public static String getPCUserId(String androidUserId) {
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return null;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = "SELECT pc_user_id FROM pairs WHERE android_user_id = ?";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, androidUserId);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("pc_user_id");
                    }
                }
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to get PC user ID: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * Delete a pair
     */
    public static void deletePair(String pcUserId, String androidUserId) {
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = "DELETE FROM pairs WHERE pc_user_id = ? AND android_user_id = ?";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, pcUserId);
                stmt.setString(2, androidUserId);
                int rowsDeleted = stmt.executeUpdate();
                AdminLogger.info(TAG, "Pair deleted: " + rowsDeleted + " row(s) affected");
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to delete pair: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Delete all pairs
     */
    public static void deleteAllPairs() {
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = "DELETE FROM pairs";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                int rowsDeleted = stmt.executeUpdate();
                AdminLogger.info(TAG, "All pairs deleted: " + rowsDeleted + " row(s) affected");
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to delete all pairs: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Load all pairs from database into memory
     */
    public static void loadAllPairs(Map<String, String> tokenPairs) {
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = "SELECT pc_user_id, android_user_id FROM pairs";
            try (PreparedStatement stmt = conn.prepareStatement(sql);
                 ResultSet rs = stmt.executeQuery()) {
                
                int count = 0;
                while (rs.next()) {
                    String pcUserId = rs.getString("pc_user_id");
                    String androidUserId = rs.getString("android_user_id");
                    
                    // Add bidirectional mapping
                    tokenPairs.put(pcUserId, androidUserId);
                    tokenPairs.put(androidUserId, pcUserId);
                    count++;
                }
                AdminLogger.info(TAG, "Loaded " + count + " pairs from database");
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to load pairs: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Record file transfer in database
     */
    public static void recordFileTransfer(String pcUserId, String androidUserId, 
                                         String fileName, long fileSize, 
                                         String fromClient, String toClient, 
                                         String ipAddress, boolean success, String details) {
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = """
                INSERT INTO file_transfers (
                    pc_user_id, android_user_id, file_name, file_size, 
                    from_client, to_client, ip_address, success, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, pcUserId);
                stmt.setString(2, androidUserId);
                stmt.setString(3, fileName);
                stmt.setLong(4, fileSize);
                stmt.setString(5, fromClient);
                stmt.setString(6, toClient);
                stmt.setString(7, ipAddress);
                stmt.setBoolean(8, success);
                stmt.setString(9, details);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to record file transfer: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Get file transfer history for a user
     */
    public static List<FileTransferRecord> getFileTransfers(String userId, int limit) {
        List<FileTransferRecord> transfers = new ArrayList<>();
        
        if (dataSource == null) {
            AdminLogger.error(TAG, "Database not initialized");
            return transfers;
        }
        
        try (Connection conn = dataSource.getConnection()) {
            String sql = """
                SELECT * FROM file_transfers 
                WHERE pc_user_id = ? OR android_user_id = ?
                ORDER BY transfer_completed_at DESC
                LIMIT ?
            """;
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, userId);
                stmt.setString(2, userId);
                stmt.setInt(3, limit);
                
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        FileTransferRecord record = new FileTransferRecord();
                        record.fileName = rs.getString("file_name");
                        record.fileSize = rs.getLong("file_size");
                        record.fromClient = rs.getString("from_client");
                        record.toClient = rs.getString("to_client");
                        record.ipAddress = rs.getString("ip_address");
                        record.success = rs.getBoolean("success");
                        record.transferCompletedAt = rs.getTimestamp("transfer_completed_at");
                        record.details = rs.getString("details");
                        transfers.add(record);
                    }
                }
            }
        } catch (SQLException e) {
            AdminLogger.error(TAG, "Failed to get file transfers: " + e.getMessage());
            e.printStackTrace();
        }
        
        return transfers;
    }
    
    /**
     * Close database connection pool
     */
    public static synchronized void close() {
        if (dataSource != null) {
            dataSource.close();
            dataSource = null;
            AdminLogger.info(TAG, "Database connection pool closed");
        }
    }
    
    /**
     * File transfer record data class
     */
    public static class FileTransferRecord {
        public String fileName;
        public long fileSize;
        public String fromClient;
        public String toClient;
        public String ipAddress;
        public boolean success;
        public Timestamp transferCompletedAt;
        public String details;
    }
}

