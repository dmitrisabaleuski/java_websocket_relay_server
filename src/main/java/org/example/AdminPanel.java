package org.example;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import org.example.utils.AdminLogger;
import org.json.JSONObject;

/**
 * Manages the admin panel and web interface
 */
public class AdminPanel {
    
    /**
     * Handle admin page request
     */
    public static void handleAdminPage(ChannelHandlerContext ctx, FullHttpRequest req) {
        String html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>HomeCloud Admin Panel</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .login-form { text-align: center; }
                    input[type="text"], input[type="password"] { padding: 12px; margin: 10px; width: 250px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
                    button { padding: 12px 30px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
                    button:hover { background: #0056b3; }
                    .error { color: red; margin: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>HomeCloud Admin Panel</h1>
                    <div class="login-form">
                        <h2>Login</h2>
                        <form id="loginForm">
                            <input type="text" id="username" placeholder="Username" required><br>
                            <input type="password" id="password" placeholder="Password" required><br>
                            <button type="submit">Login</button>
                        </form>
                        <div id="error" class="error"></div>
                    </div>
                </div>
                <script>
                    document.getElementById('loginForm').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const username = document.getElementById('username').value;
                        const password = document.getElementById('password').value;
                        
                        try {
                            const response = await fetch('/admin/login', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ username, password })
                            });
                            
                            if (response.ok) {
                                const data = await response.json();
                                localStorage.setItem('adminToken', data.token);
                                window.location.href = '/admin/dashboard';
                            } else {
                                document.getElementById('error').textContent = 'Invalid credentials';
                            }
                        } catch (error) {
                            document.getElementById('error').textContent = 'Login failed';
                        }
                    });
                </script>
            </body>
            </html>
            """;
        
        ByteBuf content = Unpooled.copiedBuffer(html, CharsetUtil.UTF_8);
        FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=UTF-8");
        resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        
        sendHttpResponse(ctx, req, resp);
        AdminLogger.log("INFO", "ADMIN", "Admin page accessed");
    }
    
    /**
     * Handle admin login request
     */
    public static void handleAdminLogin(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            String body = req.content().toString(CharsetUtil.UTF_8);
            JSONObject json = new JSONObject(body);
            String username = json.optString("username");
            String password = json.optString("password");
            
            if (AdminLogger.validateCredentials(username, password)) {
                String sessionToken = AdminLogger.createSession(username);
                
                JSONObject response = new JSONObject();
                response.put("success", true);
                response.put("token", sessionToken);
                response.put("message", "Login successful");
                
                ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
                resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
                AdminLogger.log("INFO", "ADMIN", "Admin login successful: " + username);
            } else {
                JSONObject response = new JSONObject();
                response.put("success", false);
                response.put("message", "Invalid credentials");
                
                ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
                FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED, content);
                resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
                
                sendHttpResponse(ctx, req, resp);
                AdminLogger.log("WARN", "ADMIN", "Admin login failed: " + username);
            }
        } catch (Exception e) {
            sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
        }
    }
    
    /**
     * Handle admin dashboard request
     */
    public static void handleAdminDashboard(ChannelHandlerContext ctx, FullHttpRequest req) {
        String html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>HomeCloud Admin Dashboard</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                    .container { max-width: 1400px; margin: 0 auto; }
                    .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
                    .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .stat-card h3 { margin: 0 0 15px 0; color: #333; }
                    .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
                    .clients-table { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                    .logs-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #f8f9fa; font-weight: bold; }
                    .refresh-btn { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 10px 0; }
                    .refresh-btn:hover { background: #218838; }
                    .logout-btn { padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; float: right; }
                    .logout-btn:hover { background: #c82333; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>HomeCloud Admin Dashboard</h1>
                        <button class="logout-btn" onclick="logout()">Logout</button>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <h3>Server Statistics</h3>
                            <div id="serverStats">Loading...</div>
                        </div>
                        <div class="stat-card">
                            <h3>Memory Usage</h3>
                            <div id="memoryStats">Loading...</div>
                        </div>
                        <div class="stat-card">
                            <h3>Active Transfers</h3>
                            <div id="transferStats">Loading...</div>
                        </div>
                    </div>
                    
                    <div class="clients-table">
                        <h3>Connected Clients</h3>
                        <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
                        <div id="clientsTable">Loading...</div>
                    </div>
                    
                    <div class="logs-container">
                        <h3>Server Logs</h3>
                        <div id="logsContainer">Loading...</div>
                    </div>
                </div>
                
                <script>
                    let refreshInterval;
                    
                    function refreshData() {
                        loadStats();
                        loadClients();
                        loadLogs();
                    }
                    
                    async function loadStats() {
                        try {
                            const response = await fetch('/api/stats');
                            const data = await response.json();
                            
                            document.getElementById('serverStats').innerHTML = `
                                <div class="stat-value">${data.totalClients}</div>
                                <div>Total Clients</div>
                                <div class="stat-value">${Math.round(data.serverUptime / 1000 / 60)}m</div>
                                <div>Uptime</div>
                            `;
                            
                            const memoryMB = Math.round(data.memoryUsed / 1024 / 1024);
                            const totalMB = Math.round(data.memoryTotal / 1024 / 1024);
                            document.getElementById('memoryStats').innerHTML = `
                                <div class="stat-value">${memoryMB}MB</div>
                                <div>Used Memory</div>
                                <div class="stat-value">${totalMB}MB</div>
                                <div>Total Memory</div>
                            `;
                            
                            document.getElementById('transferStats').innerHTML = `
                                <div class="stat-value">${data.activeTransfers}</div>
                                <div>Active Transfers</div>
                                <div class="stat-value">${data.totalFileTransfers}</div>
                                <div>Total Transfers</div>
                            `;
                        } catch (error) {
                            console.error('Error loading stats:', error);
                        }
                    }
                    
                    async function loadClients() {
                        try {
                            const response = await fetch('/api/clients');
                            const data = await response.json();
                            
                            let tableHtml = '<table><tr><th>User ID</th><th>Status</th><th>Remote Address</th><th>Connected</th></tr>';
                            data.clients.forEach(client => {
                                const connected = client.connected ? '🟢 Online' : '🔴 Offline';
                                const time = new Date(client.connectionTime).toLocaleTimeString();
                                tableHtml += `<tr><td>${client.userId}</td><td>${connected}</td><td>${client.remoteAddress}</td><td>${time}</td></tr>`;
                            });
                            tableHtml += '</table>';
                            
                            document.getElementById('clientsTable').innerHTML = tableHtml;
                        } catch (error) {
                            console.error('Error loading clients:', error);
                        }
                    }
                    
                    async function loadLogs() {
                        try {
                            const response = await fetch('/api/logs');
                            const data = await response.json();
                            
                            let logsHtml = '<div style="max-height: 400px; overflow-y: auto;">';
                            data.logs.slice(-50).reverse().forEach(log => {
                                logsHtml += `<div style="padding: 5px; border-bottom: 1px solid #eee;">${log}</div>`;
                            });
                            logsHtml += '</div>';
                            
                            document.getElementById('logsContainer').innerHTML = logsHtml;
                        } catch (error) {
                            console.error('Error loading logs:', error);
                        }
                    }
                    
                    function logout() {
                        localStorage.removeItem('adminToken');
                        window.location.href = '/admin';
                    }
                    
                    // Auto-refresh every 5 seconds
                    refreshInterval = setInterval(refreshData, 5000);
                    
                    // Initial load
                    refreshData();
                </script>
            </body>
            </html>
            """;
        
        ByteBuf content = Unpooled.copiedBuffer(html, CharsetUtil.UTF_8);
        FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=UTF-8");
        resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        
        sendHttpResponse(ctx, req, resp);
        AdminLogger.log("INFO", "ADMIN", "Admin dashboard accessed");
    }
    
    /**
     * Send HTTP response
     */
    private static void sendHttpResponse(ChannelHandlerContext ctx, FullHttpRequest req, FullHttpResponse res) {
        ctx.channel().writeAndFlush(res);
        if (!HttpUtil.isKeepAlive(req) || res.status().code() != 200) {
            ctx.channel().close();
        }
    }
}
