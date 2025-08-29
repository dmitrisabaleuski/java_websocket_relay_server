package org.example;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.util.CharsetUtil;
import org.example.utils.AdminLogger;
import org.example.utils.ServerConfig;
import org.json.JSONObject;
import org.json.JSONArray;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import io.netty.channel.Channel;
import java.io.File;
import java.io.FileOutputStream;

/**
 * Simplified UnifiedServerHandler using new modules
 */
public class UnifiedServerHandler extends SimpleChannelInboundHandler<Object> {
    
    private WebSocketServerHandshaker handshaker;
    private String userId;
    
    // Client management
    private static final Map<String, Channel> clients = new ConcurrentHashMap<>();
    
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof FullHttpRequest) {
            FullHttpRequest req = (FullHttpRequest) msg;
            
            // Route HTTP requests
            if ("/api/token".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.POST) {
                handleTokenRequest(ctx, req);
            } else if ("/api/stats".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                handleStatsRequest(ctx, req);
            } else if ("/api/clients".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                handleClientsRequest(ctx, req);
            } else if ("/api/logs".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                handleLogsRequest(ctx, req);
            } else if ("/admin".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                AdminPanel.handleAdminPage(ctx, req);
            } else if ("/admin/login".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.POST) {
                AdminPanel.handleAdminLogin(ctx, req);
            } else if ("/admin/dashboard".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                AdminPanel.handleAdminDashboard(ctx, req);
            } else if ("/health".equalsIgnoreCase(req.uri()) && req.method() == HttpMethod.GET) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
            } else if ("websocket".equalsIgnoreCase(req.headers().get("Upgrade"))) {
                handleWebSocketHandshake(ctx, req);
            } else {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND));
            }
        } else if (msg instanceof WebSocketFrame) {
            handleWebSocketFrame(ctx, (WebSocketFrame) msg);
        }
    }
    
    private void handleTokenRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            String body = req.content().toString(CharsetUtil.UTF_8);
            JSONObject json = new JSONObject(body);
            String userId = json.optString("userId");
            
            if (userId == null || userId.isEmpty()) {
                sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED));
                return;
            }
            
            // Create JWT token (simplified)
            String token = "JWT_" + userId + "_" + System.currentTimeMillis();
            ByteBuf content = Unpooled.copiedBuffer(token, CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            AdminLogger.log("INFO", "TOKEN", "Token issued for userId=" + userId);
        } catch (Exception e) {
            sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
        }
    }
    
    private void handleStatsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            JSONObject stats = ServerStatistics.getStatistics();
            ByteBuf content = Unpooled.copiedBuffer(stats.toString(), CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            AdminLogger.log("INFO", "ADMIN", "Stats requested");
        } catch (Exception e) {
            sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
        }
    }
    
    private void handleClientsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            JSONObject response = new JSONObject();
            JSONArray clientsArray = new JSONArray();
            
            for (Map.Entry<String, Channel> entry : clients.entrySet()) {
                JSONObject client = new JSONObject();
                client.put("userId", entry.getKey());
                client.put("connected", entry.getValue().isActive());
                client.put("remoteAddress", entry.getValue().remoteAddress().toString());
                client.put("connectionTime", System.currentTimeMillis());
                clientsArray.put(client);
            }
            
            response.put("clients", clientsArray);
            response.put("total", clients.size());
            
            ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            AdminLogger.log("INFO", "ADMIN", "Clients list requested");
        } catch (Exception e) {
            sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
        }
    }
    
    private void handleLogsRequest(ChannelHandlerContext ctx, FullHttpRequest req) {
        try {
            JSONObject response = new JSONObject();
            JSONArray logsArray = new JSONArray();
            
            for (String log : AdminLogger.getLogs()) {
                logsArray.put(log);
            }
            
            response.put("logs", logsArray);
            response.put("total", AdminLogger.getLogsCount());
            
            ByteBuf content = Unpooled.copiedBuffer(response.toString(), CharsetUtil.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            
            sendHttpResponse(ctx, req, resp);
            AdminLogger.log("INFO", "ADMIN", "Logs requested");
        } catch (Exception e) {
            sendHttpResponse(ctx, req, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR));
        }
    }
    
    private void handleWebSocketHandshake(ChannelHandlerContext ctx, FullHttpRequest req) {
        String wsUrl = "ws://" + req.headers().get(HttpHeaderNames.HOST) + req.uri();
        WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory(wsUrl, null, true);
        handshaker = wsFactory.newHandshaker(req);
        
        if (handshaker != null) {
            handshaker.handshake(ctx.channel(), req);
            AdminLogger.log("INFO", "WS", "WebSocket handshake completed");
        } else {
            WebSocketServerHandshakerFactory.sendUnsupportedVersionResponse(ctx.channel());
        }
    }
    
    private void handleWebSocketFrame(ChannelHandlerContext ctx, WebSocketFrame frame) {
        if (frame instanceof TextWebSocketFrame) {
            String message = ((TextWebSocketFrame) frame).text();
            handleTextMessage(ctx, message);
        } else if (frame instanceof BinaryWebSocketFrame) {
            handleBinaryMessage(ctx, (BinaryWebSocketFrame) frame);
        } else if (frame instanceof CloseWebSocketFrame) {
            ctx.channel().close();
        }
    }
    
    private void handleTextMessage(ChannelHandlerContext ctx, String message) {
        if (message.startsWith("AUTH:")) {
            String jwt = message.substring("AUTH:".length());
            userId = extractUserIdFromToken(jwt);
            
            if (userId != null) {
                clients.put(userId, ctx.channel());
                ctx.channel().writeAndFlush(new TextWebSocketFrame("REGISTERED:" + userId));
                ServerStatistics.setActiveConnections(clients.size());
                AdminLogger.log("INFO", "AUTH", "Client registered: userId=" + userId);
            } else {
                ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:Invalid JWT"));
                ctx.close();
            }
        }
    }
    
    private void handleBinaryMessage(ChannelHandlerContext ctx, BinaryWebSocketFrame frame) {
        try {
            // Получаем данные файла
            ByteBuf content = frame.content();
            byte[] fileData = new byte[content.readableBytes()];
            content.readBytes(fileData);
            
            // Создаем файл в папке uploads
            String fileName = "file_" + System.currentTimeMillis() + ".bin";
            File uploadsDir = new File(ServerConfig.getUploadsDir());
            if (!uploadsDir.exists()) {
                uploadsDir.mkdirs();
            }
            
            File file = new File(uploadsDir, fileName);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(fileData);
            }
            
            // Отправляем подтверждение
            ctx.channel().writeAndFlush(new TextWebSocketFrame("FILE_RECEIVED:" + fileName));
            
            // Обновляем статистику
            ServerStatistics.incrementFileTransfers();
            ServerStatistics.addBytesTransferred(fileData.length);
            
            AdminLogger.log("INFO", "FILE", "File received: " + fileName + " (" + fileData.length + " bytes)");
            
        } catch (Exception e) {
            AdminLogger.log("ERROR", "FILE", "Error processing file: " + e.getMessage());
            ctx.channel().writeAndFlush(new TextWebSocketFrame("ERROR:File processing failed"));
        }
    }
    
    private String extractUserIdFromToken(String token) {
        // Simplified token validation
        if (token.startsWith("JWT_")) {
            String[] parts = token.split("_");
            if (parts.length >= 2) {
                return parts[1];
            }
        }
        return null;
    }
    
    private void sendHttpResponse(ChannelHandlerContext ctx, FullHttpRequest req, FullHttpResponse res) {
        ctx.channel().writeAndFlush(res);
        if (!HttpUtil.isKeepAlive(req) || res.status().code() != 200) {
            ctx.channel().close();
        }
    }
    
    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (userId != null) {
            clients.remove(userId);
            ServerStatistics.setActiveConnections(clients.size());
            AdminLogger.log("INFO", "SERVER", "Client disconnected: userId=" + userId);
        }
    }
    
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        AdminLogger.log("ERROR", "EXCEPTION", cause.getMessage());
        cause.printStackTrace();
        ctx.close();
    }
}
