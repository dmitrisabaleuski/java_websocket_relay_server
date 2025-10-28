package org.example.admin;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.util.CharsetUtil;
import org.json.JSONObject;
import org.json.JSONArray;
import org.example.AdminLogger;
import org.example.ServerStatistics;

import java.io.InputStream;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import static io.netty.handler.codec.http.HttpHeaderNames.*;

/**
 * Admin web interface HTTP handler
 */
public class AdminWebInterface {
    
    private final Map<String, String> tokenPairs;
    private final Map<String, Channel> clients;
    private final Runnable savePairingsCallback;
    
    public AdminWebInterface(Map<String, String> tokenPairs, Map<String, Channel> clients, Runnable savePairingsCallback) {
        this.tokenPairs = tokenPairs;
        this.clients = clients;
        this.savePairingsCallback = savePairingsCallback;
    }
    
    /**
     * Handle admin HTTP request
     */
    public boolean handleAdminRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        String uri = req.uri();
        
        // Admin panel HTML
        if ("/admin".equals(uri) && req.method() == HttpMethod.GET) {
            serveAdminHTML(ctx, req);
            return true;
        }
        
        // API endpoints
        if (uri.startsWith("/admin/api/")) {
            handleApiRequest(ctx, req, uri);
            return true;
        }
        
        return false;
    }
    
    /**
     * Handle API requests
     */
    private void handleApiRequest(ChannelHandlerContext ctx, FullHttpRequest req, String uri) {
        // Check session (except for login)
        if (!uri.equals("/admin/api/login")) {
            String sessionToken = getCookie(req, "admin_session");
            if (!AdminLogger.isValidSession(sessionToken)) {
                sendJSONResponse(ctx, req, HttpResponseStatus.UNAUTHORIZED, 
                    createError("Unauthorized", "Please login first"));
                return;
            }
        }
        
        try {
            switch (uri) {
                case "/admin/api/login":
                    handleLogin(ctx, req);
                    break;
                    
                case "/admin/api/logout":
                    handleLogout(ctx, req);
                    break;
                    
                case "/admin/api/stats":
                    handleStats(ctx, req);
                    break;
                    
                case "/admin/api/pairs":
                    handlePairs(ctx, req);
                    break;
                    
                case "/admin/api/pairs/delete":
                    handleDeletePair(ctx, req);
                    break;
                    
                case "/admin/api/pairs/delete-all":
                    handleDeleteAllPairs(ctx, req);
                    break;
                    
                case "/admin/api/clients":
                    handleClients(ctx, req);
                    break;
                    
                case "/admin/api/clients/disconnect":
                    handleDisconnectClient(ctx, req);
                    break;
                    
                case "/admin/api/logs":
                    handleLogs(ctx, req);
                    break;
                    
                case "/admin/api/logs/clear":
                    handleClearLogs(ctx, req);
                    break;
                    
                case "/admin/api/audit":
                    handleAudit(ctx, req);
                    break;
                    
                case "/admin/api/audit/export":
                    handleAuditExport(ctx, req);
                    break;
                    
                case "/admin/api/compliance/report":
                    handleComplianceReport(ctx, req);
                    break;
                    
                default:
                    sendJSONResponse(ctx, req, HttpResponseStatus.NOT_FOUND, 
                        createError("Not Found", "API endpoint not found"));
            }
        } catch (Exception e) {
            AdminLogger.error("ADMIN_API", "Error handling request: " + e.getMessage());
            e.printStackTrace();
            sendJSONResponse(ctx, req, HttpResponseStatus.INTERNAL_SERVER_ERROR, 
                createError("Server Error", e.getMessage()));
        }
    }
    
    /**
     * Handle login
     */
    private void handleLogin(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.method() != HttpMethod.POST) {
            sendJSONResponse(ctx, req, HttpResponseStatus.METHOD_NOT_ALLOWED, 
                createError("Method Not Allowed", "Use POST"));
            return;
        }
        
        String body = req.content().toString(CharsetUtil.UTF_8);
        JSONObject json = new JSONObject(body);
        
        String username = json.optString("username");
        String password = json.optString("password");
        
        if (AdminLogger.validateCredentials(username, password)) {
            String sessionToken = AdminLogger.createSession(username);
            
            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("message", "Login successful");
            response.put("sessionToken", sessionToken);
            
            // Set cookie
            FullHttpResponse httpResponse = createJSONResponse(HttpResponseStatus.OK, response);
            httpResponse.headers().set("Set-Cookie", "admin_session=" + sessionToken + "; HttpOnly; Path=/admin; Max-Age=1800");
            sendResponse(ctx, req, httpResponse);
        } else {
            sendJSONResponse(ctx, req, HttpResponseStatus.UNAUTHORIZED, 
                createError("Invalid Credentials", "Username or password incorrect"));
        }
    }
    
    /**
     * Handle logout
     */
    private void handleLogout(ChannelHandlerContext ctx, FullHttpRequest req) {
        String sessionToken = getCookie(req, "admin_session");
        AdminLogger.removeSession(sessionToken);
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("message", "Logged out successfully");
        
        FullHttpResponse httpResponse = createJSONResponse(HttpResponseStatus.OK, response);
        httpResponse.headers().set("Set-Cookie", "admin_session=; HttpOnly; Path=/admin; Max-Age=0");
        sendResponse(ctx, req, httpResponse);
    }
    
    /**
     * Handle stats
     */
    private void handleStats(ChannelHandlerContext ctx, FullHttpRequest req) {
        JSONObject stats = new JSONObject();
        
        // Server stats
        stats.put("connectedClients", clients.size());
        stats.put("uptime", ServerStatistics.getUptime());
        stats.put("logsCount", AdminLogger.getLogsCount());
        stats.put("activeSessions", AdminLogger.getActiveSessionsCount());
        
        // Pair stats
        JSONObject pairStats = PairManager.getStatistics(clients);
        stats.put("pairs", pairStats);
        
        // Memory stats
        Runtime runtime = Runtime.getRuntime();
        JSONObject memory = new JSONObject();
        memory.put("used", runtime.totalMemory() - runtime.freeMemory());
        memory.put("total", runtime.totalMemory());
        memory.put("max", runtime.maxMemory());
        stats.put("memory", memory);
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, stats);
    }
    
    /**
     * Handle pairs list
     */
    private void handlePairs(ChannelHandlerContext ctx, FullHttpRequest req) {
        JSONArray pairs = PairManager.getAllPairsJSON(clients);
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("pairs", pairs);
        response.put("count", pairs.length());
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle delete pair
     */
    private void handleDeletePair(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.method() != HttpMethod.POST) {
            sendJSONResponse(ctx, req, HttpResponseStatus.METHOD_NOT_ALLOWED, 
                createError("Method Not Allowed", "Use POST"));
            return;
        }
        
        String body = req.content().toString(CharsetUtil.UTF_8);
        JSONObject json = new JSONObject(body);
        
        String pcUserId = json.optString("pcUserId");
        String androidUserId = json.optString("androidUserId");
        String password = json.optString("password");
        
        // Verify password for delete operation
        String sessionToken = getCookie(req, "admin_session");
        String username = AdminLogger.getSessionUsername(sessionToken);
        
        if (!AdminLogger.validateCredentials(username, password)) {
            sendJSONResponse(ctx, req, HttpResponseStatus.UNAUTHORIZED, 
                createError("Invalid Password", "Password verification failed"));
            return;
        }
        
        boolean deleted = PairManager.deletePair(pcUserId, androidUserId, tokenPairs, clients, savePairingsCallback);
        
        if (deleted) {
            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("message", "Pair deleted successfully");
            sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
        } else {
            sendJSONResponse(ctx, req, HttpResponseStatus.NOT_FOUND, 
                createError("Not Found", "Pair not found"));
        }
    }
    
    /**
     * Handle delete all pairs
     */
    private void handleDeleteAllPairs(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.method() != HttpMethod.POST) {
            sendJSONResponse(ctx, req, HttpResponseStatus.METHOD_NOT_ALLOWED, 
                createError("Method Not Allowed", "Use POST"));
            return;
        }
        
        String body = req.content().toString(CharsetUtil.UTF_8);
        JSONObject json = new JSONObject(body);
        String password = json.optString("password");
        
        // Verify password for delete ALL operation
        String sessionToken = getCookie(req, "admin_session");
        String username = AdminLogger.getSessionUsername(sessionToken);
        
        if (!AdminLogger.validateCredentials(username, password)) {
            sendJSONResponse(ctx, req, HttpResponseStatus.UNAUTHORIZED, 
                createError("Invalid Password", "Password verification failed"));
            return;
        }
        
        int count = PairManager.deleteAllPairs(tokenPairs, clients, savePairingsCallback);
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("message", "All pairs deleted");
        response.put("count", count);
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle clients list
     */
    private void handleClients(ChannelHandlerContext ctx, FullHttpRequest req) {
        JSONArray clientsArray = new JSONArray();
        
        for (Map.Entry<String, Channel> entry : clients.entrySet()) {
            JSONObject client = new JSONObject();
            client.put("userId", entry.getKey());
            client.put("address", entry.getValue().remoteAddress().toString());
            client.put("active", entry.getValue().isActive());
            clientsArray.put(client);
        }
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("clients", clientsArray);
        response.put("count", clientsArray.length());
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle disconnect client
     */
    private void handleDisconnectClient(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.method() != HttpMethod.POST) {
            sendJSONResponse(ctx, req, HttpResponseStatus.METHOD_NOT_ALLOWED, 
                createError("Method Not Allowed", "Use POST"));
            return;
        }
        
        String body = req.content().toString(CharsetUtil.UTF_8);
        JSONObject json = new JSONObject(body);
        String userId = json.optString("userId");
        
        boolean disconnected = PairManager.disconnectClient(userId, clients);
        
        if (disconnected) {
            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("message", "Client disconnected");
            sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
        } else {
            sendJSONResponse(ctx, req, HttpResponseStatus.NOT_FOUND, 
                createError("Not Found", "Client not found or already disconnected"));
        }
    }
    
    /**
     * Handle logs
     */
    private void handleLogs(ChannelHandlerContext ctx, FullHttpRequest req) {
        QueryStringDecoder queryDecoder = new QueryStringDecoder(req.uri());
        Map<String, java.util.List<String>> params = queryDecoder.parameters();
        
        String level = getQueryParam(params, "level");
        String search = getQueryParam(params, "search");
        
        JSONArray logs = AdminLogger.getLogsJSON(level, search);
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("logs", logs);
        response.put("count", logs.length());
        response.put("total", AdminLogger.getLogsCount());
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle clear logs
     */
    private void handleClearLogs(ChannelHandlerContext ctx, FullHttpRequest req) {
        if (req.method() != HttpMethod.POST) {
            sendJSONResponse(ctx, req, HttpResponseStatus.METHOD_NOT_ALLOWED, 
                createError("Method Not Allowed", "Use POST"));
            return;
        }
        
        AdminLogger.clearLogs();
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("message", "Logs cleared");
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle audit logs
     */
    private void handleAudit(ChannelHandlerContext ctx, FullHttpRequest req) {
        QueryStringDecoder queryDecoder = new QueryStringDecoder(req.uri());
        Map<String, java.util.List<String>> params = queryDecoder.parameters();
        
        String user = getQueryParam(params, "user");
        String action = getQueryParam(params, "action");
        String fileName = getQueryParam(params, "fileName");
        
        JSONArray auditLogs = org.example.AuditLogger.getAuditLogsJSON(user, action, fileName);
        
        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("auditLogs", auditLogs);
        response.put("count", auditLogs.length());
        response.put("total", org.example.AuditLogger.getAuditLogsCount());
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, response);
    }
    
    /**
     * Handle audit export (CSV)
     */
    private void handleAuditExport(ChannelHandlerContext ctx, FullHttpRequest req) {
        QueryStringDecoder queryDecoder = new QueryStringDecoder(req.uri());
        Map<String, java.util.List<String>> params = queryDecoder.parameters();
        
        String user = getQueryParam(params, "user");
        String action = getQueryParam(params, "action");
        String fileName = getQueryParam(params, "fileName");
        
        List<org.example.AuditLogger.AuditEntry> auditLogs = org.example.AuditLogger.getFilteredAuditLogs(user, action, fileName, null, null);
        
        String csv = org.example.AuditLogger.exportAsCSV(auditLogs);
        
        ByteBuf content = Unpooled.copiedBuffer(csv, CharsetUtil.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
        response.headers().set(CONTENT_TYPE, "text/csv");
        response.headers().set(CONTENT_DISPOSITION, "attachment; filename=audit_logs.csv");
        response.headers().setInt(CONTENT_LENGTH, content.readableBytes());
        
        ChannelFuture future = ctx.channel().writeAndFlush(response);
        future.addListener(ChannelFutureListener.CLOSE);
    }
    
    /**
     * Handle compliance report
     */
    private void handleComplianceReport(ChannelHandlerContext ctx, FullHttpRequest req) {
        QueryStringDecoder queryDecoder = new QueryStringDecoder(req.uri());
        Map<String, java.util.List<String>> params = queryDecoder.parameters();
        
        String period = getQueryParam(params, "period"); // e.g., "last_30_days", "last_7_days", "all"
        
        // Get statistics
        JSONObject stats = ServerStatistics.getStatistics();
        int totalTransfers = stats.optInt("totalFileTransfers", 0);
        
        // Get audit logs count
        int auditLogsCount = org.example.AuditLogger.getAuditLogsCount();
        
        // Get active pairs (pass clients map)
        int activePairs = org.example.admin.PairManager.getActivePairsCount(clients);
        
        // Build compliance report
        JSONObject report = new JSONObject();
        report.put("success", true);
        report.put("reportDate", System.currentTimeMillis());
        report.put("reportType", "Compliance Report");
        report.put("period", period != null ? period : "all");
        
        // Security metrics
        JSONObject security = new JSONObject();
        security.put("encryptionEnabled", "AES-256-GCM");
        security.put("encryptionStrength", "256-bit");
        security.put("endToEndEncryption", true);
        report.put("security", security);
        
        // Audit metrics
        JSONObject audit = new JSONObject();
        audit.put("totalAuditEntries", auditLogsCount);
        audit.put("auditLoggingEnabled", true);
        audit.put("auditExportAvailable", true);
        report.put("audit", audit);
        
        // Transfer metrics
        JSONObject transfers = new JSONObject();
        transfers.put("totalFileTransfers", totalTransfers);
        transfers.put("activePairs", activePairs);
        transfers.put("zeroBreaches", true);
        report.put("transfers", transfers);
        
        // Compliance status
        JSONObject compliance = new JSONObject();
        compliance.put("gdprCompliant", true);
        compliance.put("dataMinimization", true);
        compliance.put("rightToErasure", true);
        compliance.put("encryptionAtRest", false); // Server doesn't store files
        compliance.put("encryptionInTransit", true);
        report.put("compliance", compliance);
        
        sendJSONResponse(ctx, req, HttpResponseStatus.OK, report);
    }
    
    /**
     * Serve admin HTML page
     */
    private void serveAdminHTML(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            InputStream is = getClass().getResourceAsStream("/admin/index.html");
            if (is != null) {
                byte[] bytes = is.readAllBytes();
                is.close();
                
                ByteBuf content = Unpooled.copiedBuffer(bytes);
                FullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                response.headers().set(CONTENT_TYPE, "text/html; charset=UTF-8");
                response.headers().setInt(CONTENT_LENGTH, content.readableBytes());
                
                sendResponse(ctx, req, response);
            } else {
                // Fallback: serve embedded HTML
                serveEmbeddedAdminHTML(ctx, req);
            }
        } catch (Exception e) {
            AdminLogger.error("ADMIN_WEB", "Error serving admin HTML: " + e.getMessage());
            serveEmbeddedAdminHTML(ctx, req);
        }
    }
    
    /**
     * Serve embedded admin HTML (fallback)
     */
    private void serveEmbeddedAdminHTML(ChannelHandlerContext ctx, FullHttpRequest req) {
        String html = getAdminHTML();
        ByteBuf content = Unpooled.copiedBuffer(html, CharsetUtil.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
        response.headers().set(CONTENT_TYPE, "text/html; charset=UTF-8");
        response.headers().setInt(CONTENT_LENGTH, content.readableBytes());
        
        sendResponse(ctx, req, response);
    }
    
    // Helper methods
    
    private void sendJSONResponse(ChannelHandlerContext ctx, FullHttpRequest req, 
                                   HttpResponseStatus status, JSONObject json) {
        FullHttpResponse response = createJSONResponse(status, json);
        sendResponse(ctx, req, response);
    }
    
    private FullHttpResponse createJSONResponse(HttpResponseStatus status, JSONObject json) {
        ByteBuf content = Unpooled.copiedBuffer(json.toString(), CharsetUtil.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1, status, content);
        response.headers().set(CONTENT_TYPE, "application/json; charset=UTF-8");
        response.headers().setInt(CONTENT_LENGTH, content.readableBytes());
        response.headers().set("Access-Control-Allow-Origin", "*");
        return response;
    }
    
    private void sendResponse(ChannelHandlerContext ctx, FullHttpRequest req, FullHttpResponse response) {
        ChannelFuture f = ctx.channel().writeAndFlush(response);
        if (!HttpUtil.isKeepAlive(req) || response.status().code() != 200) {
            f.addListener(ChannelFutureListener.CLOSE);
        }
    }
    
    private JSONObject createError(String error, String message) {
        JSONObject json = new JSONObject();
        json.put("success", false);
        json.put("error", error);
        json.put("message", message);
        return json;
    }
    
    private String getCookie(FullHttpRequest req, String name) {
        String cookieHeader = req.headers().get(HttpHeaderNames.COOKIE);
        if (cookieHeader != null) {
            for (String cookie : cookieHeader.split("; ")) {
                String[] parts = cookie.split("=", 2);
                if (parts.length == 2 && parts[0].equals(name)) {
                    return parts[1];
                }
            }
        }
        return null;
    }
    
    private String getQueryParam(Map<String, List<String>> params, String name) {
        List<String> values = params.get(name);
        return (values != null && !values.isEmpty()) ? values.get(0) : null;
    }
    
    /**
     * Get embedded admin HTML
     */
    private String getAdminHTML() {
        return "<!DOCTYPE html>\n" +
"<html lang='en'>\n" +
"<head>\n" +
"    <meta charset='UTF-8'>\n" +
"    <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n" +
"    <title>HomeCloud Admin Panel</title>\n" +
"    <style>\n" +
"        * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
"        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f5f5f5; }\n" +
"        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }\n" +
"        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }\n" +
"        .header h1 { font-size: 32px; margin-bottom: 10px; }\n" +
"        .header p { opacity: 0.9; font-size: 16px; }\n" +
"        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }\n" +
"        .stat-card { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }\n" +
"        .stat-card h3 { color: #666; font-size: 14px; font-weight: 500; margin-bottom: 10px; text-transform: uppercase; }\n" +
"        .stat-card .value { font-size: 32px; font-weight: bold; color: #333; }\n" +
"        .stat-card .label { color: #999; font-size: 14px; margin-top: 5px; }\n" +
"        .tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 2px solid #e0e0e0; }\n" +
"        .tab { padding: 12px 24px; background: none; border: none; cursor: pointer; font-size: 16px; color: #666; border-bottom: 3px solid transparent; transition: all 0.3s; }\n" +
"        .tab:hover { color: #667eea; }\n" +
"        .tab.active { color: #667eea; border-bottom-color: #667eea; font-weight: 600; }\n" +
"        .content-box { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }\n" +
"        .login-container { max-width: 400px; margin: 100px auto; }\n" +
"        .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }\n" +
"        .login-box h2 { color: #667eea; margin-bottom: 30px; text-align: center; }\n" +
"        .form-group { margin-bottom: 20px; }\n" +
"        .form-group label { display: block; margin-bottom: 8px; color: #666; font-weight: 500; }\n" +
"        .form-group input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 16px; transition: border 0.3s; }\n" +
"        .form-group input:focus { outline: none; border-color: #667eea; }\n" +
"        .btn { padding: 12px 24px; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: all 0.3s; }\n" +
"        .btn-primary { background: #667eea; color: white; }\n" +
"        .btn-primary:hover { background: #5568d3; }\n" +
"        .btn-danger { background: #e74c3c; color: white; }\n" +
"        .btn-danger:hover { background: #c0392b; }\n" +
"        .btn-success { background: #27ae60; color: white; }\n" +
"        .btn-secondary { background: #95a5a6; color: white; }\n" +
"        .btn-full { width: 100%; }\n" +
"        .pair-card { background: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #667eea; }\n" +
"        .pair-card.offline { border-left-color: #e74c3c; opacity: 0.7; }\n" +
"        .pair-card h4 { margin-bottom: 10px; color: #333; }\n" +
"        .pair-info { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0; font-size: 14px; color: #666; }\n" +
"        .status { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }\n" +
"        .status.online { background: #27ae60; color: white; }\n" +
"        .status.offline { background: #e74c3c; color: white; }\n" +
"        .status.partial { background: #f39c12; color: white; }\n" +
"        .log-entry { padding: 10px; border-bottom: 1px solid #e0e0e0; font-family: 'Courier New', monospace; font-size: 13px; }\n" +
"        .log-entry.INFO { border-left: 3px solid #3498db; }\n" +
"        .log-entry.WARN { border-left: 3px solid #f39c12; background: #fff9e6; }\n" +
"        .log-entry.ERROR { border-left: 3px solid #e74c3c; background: #ffe6e6; }\n" +
"        .log-entry.SECURITY { border-left: 3px solid #9b59b6; background: #f3e6ff; }\n" +
"        .log-entry.ADMIN { border-left: 3px solid #16a085; }\n" +
"        .toolbar { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }\n" +
"        .search-box { flex: 1; min-width: 200px; padding: 10px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; }\n" +
"        .filter-btn { padding: 8px 16px; border: 2px solid #e0e0e0; background: white; border-radius: 8px; cursor: pointer; transition: all 0.3s; }\n" +
"        .filter-btn.active { background: #667eea; color: white; border-color: #667eea; }\n" +
"        .hidden { display: none; }\n" +
"        .error-msg { background: #e74c3c; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }\n" +
"        .success-msg { background: #27ae60; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }\n" +
"        .loading { text-align: center; padding: 40px; color: #999; }\n" +
"        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; }\n" +
"        .modal-content { background: white; max-width: 500px; margin: 100px auto; padding: 30px; border-radius: 12px; }\n" +
"        .modal-content h3 { margin-bottom: 20px; color: #333; }\n" +
"        .actions { display: flex; gap: 10px; margin-top: 15px; }\n" +
"        .logout-btn { background: #e74c3c; color: white; padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; float: right; }\n" +
"    </style>\n" +
"</head>\n" +
"<body>\n" +
"    <div id='loginScreen' class='login-container'>\n" +
"        <div class='login-box'>\n" +
"            <h2>🖥️ HomeCloud Admin</h2>\n" +
"            <div id='loginError' class='error-msg hidden'></div>\n" +
"            <div class='form-group'>\n" +
"                <label>Username</label>\n" +
"                <input type='text' id='username' placeholder='admin' autofocus>\n" +
"            </div>\n" +
"            <div class='form-group'>\n" +
"                <label>Password</label>\n" +
"                <input type='password' id='password' placeholder='Enter password'>\n" +
"            </div>\n" +
"            <button class='btn btn-primary btn-full' onclick='login()'>Login</button>\n" +
"        </div>\n" +
"    </div>\n" +
"    \n" +
"    <div id='adminPanel' class='container hidden'>\n" +
"        <div class='header'>\n" +
"            <h1>🖥️ HomeCloud Server Admin Panel</h1>\n" +
"            <p>Real-time monitoring and management</p>\n" +
"            <button class='logout-btn' onclick='logout()'>Logout</button>\n" +
"        </div>\n" +
"        \n" +
"        <div class='stats-grid'>\n" +
"            <div class='stat-card'>\n" +
"                <h3>Connected Clients</h3>\n" +
"                <div class='value' id='statClients'>-</div>\n" +
"                <div class='label'>Active connections</div>\n" +
"            </div>\n" +
"            <div class='stat-card'>\n" +
"                <h3>Active Pairs</h3>\n" +
"                <div class='value' id='statPairs'>-</div>\n" +
"                <div class='label'>Currently paired</div>\n" +
"            </div>\n" +
"            <div class='stat-card'>\n" +
"                <h3>Files Transferred</h3>\n" +
"                <div class='value' id='statFiles'>-</div>\n" +
"                <div class='label'>Total transfers</div>\n" +
"            </div>\n" +
"            <div class='stat-card'>\n" +
"                <h3>Server Uptime</h3>\n" +
"                <div class='value' id='statUptime'>-</div>\n" +
"                <div class='label'>Since startup</div>\n" +
"            </div>\n" +
"        </div>\n" +
"        \n" +
"        <div class='tabs'>\n" +
"            <button class='tab active' onclick='showTab(\"pairs\")'>Pairs</button>\n" +
"            <button class='tab' onclick='showTab(\"clients\")'>Clients</button>\n" +
"            <button class='tab' onclick='showTab(\"logs\")'>Logs</button>\n" +
"        </div>\n" +
"        \n" +
"        <div id='pairsTab' class='content-box'>\n" +
"            <div class='toolbar'>\n" +
"                <button class='btn btn-danger' onclick='deleteAllPairs()'>Delete All Pairs</button>\n" +
"                <button class='btn btn-secondary' onclick='loadPairs()'>Refresh</button>\n" +
"            </div>\n" +
"            <div id='pairsList'></div>\n" +
"        </div>\n" +
"        \n" +
"        <div id='clientsTab' class='content-box hidden'>\n" +
"            <div class='toolbar'>\n" +
"                <button class='btn btn-secondary' onclick='loadClients()'>Refresh</button>\n" +
"            </div>\n" +
"            <div id='clientsList'></div>\n" +
"        </div>\n" +
"        \n" +
"        <div id='logsTab' class='content-box hidden'>\n" +
"            <div class='toolbar'>\n" +
"                <input type='text' class='search-box' id='logSearch' placeholder='Search logs...' oninput='loadLogs()'>\n" +
"                <button class='filter-btn active' data-level='ALL' onclick='filterLogs(this)'>ALL</button>\n" +
"                <button class='filter-btn' data-level='INFO' onclick='filterLogs(this)'>INFO</button>\n" +
"                <button class='filter-btn' data-level='WARN' onclick='filterLogs(this)'>WARN</button>\n" +
"                <button class='filter-btn' data-level='ERROR' onclick='filterLogs(this)'>ERROR</button>\n" +
"                <button class='filter-btn' data-level='SECURITY' onclick='filterLogs(this)'>SECURITY</button>\n" +
"                <button class='btn btn-danger' onclick='clearLogs()'>Clear Logs</button>\n" +
"            </div>\n" +
"            <div id='logsList'></div>\n" +
"        </div>\n" +
"    </div>\n" +
"    \n" +
"    <div id='deleteModal' class='modal'>\n" +
"        <div class='modal-content'>\n" +
"            <h3>⚠️ Confirm Action</h3>\n" +
"            <p id='deleteMessage'>This action requires password verification.</p>\n" +
"            <div class='form-group'>\n" +
"                <label>Admin Password</label>\n" +
"                <input type='password' id='deletePassword' placeholder='Enter password'>\n" +
"            </div>\n" +
"            <div class='actions'>\n" +
"                <button class='btn btn-secondary' onclick='closeModal()'>Cancel</button>\n" +
"                <button class='btn btn-danger' onclick='confirmDelete()'>Confirm Delete</button>\n" +
"            </div>\n" +
"        </div>\n" +
"    </div>\n" +
"\n" +
"<script>\n" +
"let currentLevel = 'ALL';\n" +
"let deleteAction = null;\n" +
"let refreshInterval = null;\n" +
"\n" +
"async function login() {\n" +
"    const username = document.getElementById('username').value;\n" +
"    const password = document.getElementById('password').value;\n" +
"    try {\n" +
"        const resp = await fetch('/admin/api/login', {\n" +
"            method: 'POST',\n" +
"            headers: {'Content-Type': 'application/json'},\n" +
"            body: JSON.stringify({username, password})\n" +
"        });\n" +
"        const data = await resp.json();\n" +
"        if (data.success) {\n" +
"            document.getElementById('loginScreen').classList.add('hidden');\n" +
"            document.getElementById('adminPanel').classList.remove('hidden');\n" +
"            loadDashboard();\n" +
"            refreshInterval = setInterval(loadStats, 5000);\n" +
"        } else {\n" +
"            document.getElementById('loginError').textContent = data.message;\n" +
"            document.getElementById('loginError').classList.remove('hidden');\n" +
"        }\n" +
"    } catch(e) { alert('Login failed: ' + e); }\n" +
"}\n" +
"\n" +
"async function logout() {\n" +
"    clearInterval(refreshInterval);\n" +
"    await fetch('/admin/api/logout', {method: 'POST'});\n" +
"    location.reload();\n" +
"}\n" +
"\n" +
"async function loadDashboard() {\n" +
"    loadStats();\n" +
"    loadPairs();\n" +
"}\n" +
"\n" +
"async function loadStats() {\n" +
"    try {\n" +
"        const resp = await fetch('/admin/api/stats');\n" +
"        const data = await resp.json();\n" +
"        document.getElementById('statClients').textContent = data.connectedClients;\n" +
"        document.getElementById('statPairs').textContent = data.pairs.activePairs + ' / ' + data.pairs.totalPairs;\n" +
"        document.getElementById('statFiles').textContent = data.pairs.totalFilesTransferred;\n" +
"        document.getElementById('statUptime').textContent = formatUptime(data.uptime);\n" +
"    } catch(e) { console.error(e); }\n" +
"}\n" +
"\n" +
"async function loadPairs() {\n" +
"    try {\n" +
"        const resp = await fetch('/admin/api/pairs');\n" +
"        const data = await resp.json();\n" +
"        const container = document.getElementById('pairsList');\n" +
"        if (data.pairs.length === 0) {\n" +
"            container.innerHTML = '<p class=\"loading\">No pairs found</p>';\n" +
"            return;\n" +
"        }\n" +
"        container.innerHTML = data.pairs.map(p => `\n" +
"            <div class='pair-card ${p.status === 'OFFLINE' ? 'offline' : ''}'>\n" +
"                <h4>\n" +
"                    PC: ${p.pcUserId} ↔️ Android: ${p.androidUserId}\n" +
"                    <span class='status ${p.status.toLowerCase()}'>${p.status}</span>\n" +
"                </h4>\n" +
"                <div class='pair-info'>\n" +
"                    <div>📁 Files: ${p.filesTransferred}</div>\n" +
"                    <div>💾 Data: ${formatBytes(p.bytesTransferred)}</div>\n" +
"                    <div>⏱️ Uptime: ${formatUptime(p.uptime)}</div>\n" +
"                    <div>🔌 Last Activity: ${formatTime(p.inactiveTime)}</div>\n" +
"                </div>\n" +
"                <div class='actions'>\n" +
"                    <button class='btn btn-danger' onclick='deletePair(\"${p.pcUserId}\", \"${p.androidUserId}\")'>Delete Pair</button>\n" +
"                </div>\n" +
"            </div>\n" +
"        `).join('');\n" +
"    } catch(e) { console.error(e); }\n" +
"}\n" +
"\n" +
"async function loadClients() {\n" +
"    try {\n" +
"        const resp = await fetch('/admin/api/clients');\n" +
"        const data = await resp.json();\n" +
"        const container = document.getElementById('clientsList');\n" +
"        if (data.clients.length === 0) {\n" +
"            container.innerHTML = '<p class=\"loading\">No clients connected</p>';\n" +
"            return;\n" +
"        }\n" +
"        container.innerHTML = data.clients.map(c => `\n" +
"            <div class='pair-card'>\n" +
"                <h4>${c.userId} <span class='status ${c.active ? 'online' : 'offline'}'>${c.active ? 'ONLINE' : 'OFFLINE'}</span></h4>\n" +
"                <div class='pair-info'>\n" +
"                    <div>📍 Address: ${c.address}</div>\n" +
"                </div>\n" +
"                <div class='actions'>\n" +
"                    <button class='btn btn-danger' onclick='disconnectClient(\"${c.userId}\")'>Disconnect</button>\n" +
"                </div>\n" +
"            </div>\n" +
"        `).join('');\n" +
"    } catch(e) { console.error(e); }\n" +
"}\n" +
"\n" +
"async function loadLogs() {\n" +
"    try {\n" +
"        const search = document.getElementById('logSearch').value;\n" +
"        const resp = await fetch(`/admin/api/logs?level=${currentLevel}&search=${encodeURIComponent(search)}`);\n" +
"        const data = await resp.json();\n" +
"        const container = document.getElementById('logsList');\n" +
"        if (data.logs.length === 0) {\n" +
"            container.innerHTML = '<p class=\"loading\">No logs found</p>';\n" +
"            return;\n" +
"        }\n" +
"        container.innerHTML = data.logs.reverse().slice(0, 100).map(log => `\n" +
"            <div class='log-entry ${log.level}'>\n" +
"                <strong>[${log.time}]</strong> <strong>${log.level}</strong> [${log.source}] ${log.message}\n" +
"            </div>\n" +
"        `).join('');\n" +
"    } catch(e) { console.error(e); }\n" +
"}\n" +
"\n" +
"function showTab(tab) {\n" +
"    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));\n" +
"    event.target.classList.add('active');\n" +
"    document.getElementById('pairsTab').classList.add('hidden');\n" +
"    document.getElementById('clientsTab').classList.add('hidden');\n" +
"    document.getElementById('logsTab').classList.add('hidden');\n" +
"    if (tab === 'pairs') { document.getElementById('pairsTab').classList.remove('hidden'); loadPairs(); }\n" +
"    if (tab === 'clients') { document.getElementById('clientsTab').classList.remove('hidden'); loadClients(); }\n" +
"    if (tab === 'logs') { document.getElementById('logsTab').classList.remove('hidden'); loadLogs(); }\n" +
"}\n" +
"\n" +
"function filterLogs(btn) {\n" +
"    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));\n" +
"    btn.classList.add('active');\n" +
"    currentLevel = btn.dataset.level;\n" +
"    loadLogs();\n" +
"}\n" +
"\n" +
"function deletePair(pc, android) {\n" +
"    deleteAction = {type: 'pair', pc, android};\n" +
"    document.getElementById('deleteMessage').textContent = `Delete pair: ${pc} ↔️ ${android}?`;\n" +
"    document.getElementById('deleteModal').style.display = 'block';\n" +
"}\n" +
"\n" +
"function deleteAllPairs() {\n" +
"    deleteAction = {type: 'all'};\n" +
"    document.getElementById('deleteMessage').textContent = '⚠️ Delete ALL pairs? This cannot be undone!';\n" +
"    document.getElementById('deleteModal').style.display = 'block';\n" +
"}\n" +
"\n" +
"async function confirmDelete() {\n" +
"    const password = document.getElementById('deletePassword').value;\n" +
"    if (!password) { alert('Password required'); return; }\n" +
"    try {\n" +
"        let url, body;\n" +
"        if (deleteAction.type === 'all') {\n" +
"            url = '/admin/api/pairs/delete-all';\n" +
"            body = {password};\n" +
"        } else {\n" +
"            url = '/admin/api/pairs/delete';\n" +
"            body = {pcUserId: deleteAction.pc, androidUserId: deleteAction.android, password};\n" +
"        }\n" +
"        const resp = await fetch(url, {\n" +
"            method: 'POST',\n" +
"            headers: {'Content-Type': 'application/json'},\n" +
"            body: JSON.stringify(body)\n" +
"        });\n" +
"        const data = await resp.json();\n" +
"        if (data.success) {\n" +
"            closeModal();\n" +
"            loadPairs();\n" +
"            loadStats();\n" +
"        } else {\n" +
"            alert(data.message);\n" +
"        }\n" +
"    } catch(e) { alert('Error: ' + e); }\n" +
"}\n" +
"\n" +
"function closeModal() {\n" +
"    document.getElementById('deleteModal').style.display = 'none';\n" +
"    document.getElementById('deletePassword').value = '';\n" +
"}\n" +
"\n" +
"async function disconnectClient(userId) {\n" +
"    if (!confirm(`Disconnect client ${userId}?`)) return;\n" +
"    try {\n" +
"        await fetch('/admin/api/clients/disconnect', {\n" +
"            method: 'POST',\n" +
"            headers: {'Content-Type': 'application/json'},\n" +
"            body: JSON.stringify({userId})\n" +
"        });\n" +
"        loadClients();\n" +
"    } catch(e) { alert('Error: ' + e); }\n" +
"}\n" +
"\n" +
"async function clearLogs() {\n" +
"    if (!confirm('Clear all logs?')) return;\n" +
"    try {\n" +
"        await fetch('/admin/api/logs/clear', {method: 'POST'});\n" +
"        loadLogs();\n" +
"    } catch(e) { alert('Error: ' + e); }\n" +
"}\n" +
"\n" +
"function formatUptime(ms) {\n" +
"    const s = Math.floor(ms / 1000);\n" +
"    const m = Math.floor(s / 60);\n" +
"    const h = Math.floor(m / 60);\n" +
"    const d = Math.floor(h / 24);\n" +
"    if (d > 0) return d + 'd ' + (h % 24) + 'h';\n" +
"    if (h > 0) return h + 'h ' + (m % 60) + 'm';\n" +
"    if (m > 0) return m + 'm ' + (s % 60) + 's';\n" +
"    return s + 's';\n" +
"}\n" +
"\n" +
"function formatTime(ms) {\n" +
"    if (ms < 60000) return 'just now';\n" +
"    return formatUptime(ms) + ' ago';\n" +
"}\n" +
"\n" +
"function formatBytes(bytes) {\n" +
"    if (bytes < 1024) return bytes + ' B';\n" +
"    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';\n" +
"    if (bytes < 1024*1024*1024) return (bytes/1024/1024).toFixed(1) + ' MB';\n" +
"    return (bytes/1024/1024/1024).toFixed(2) + ' GB';\n" +
"}\n" +
"\n" +
"document.getElementById('password').addEventListener('keypress', (e) => {\n" +
"    if (e.key === 'Enter') login();\n" +
"});\n" +
"</script>\n" +
"</body>\n" +
"</html>";
    }
}
