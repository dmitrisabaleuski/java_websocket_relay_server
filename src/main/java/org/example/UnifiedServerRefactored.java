package org.example;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import org.example.utils.AdminLogger;
import org.example.utils.ServerConfig;
import org.example.UnifiedServerHandler;

import java.io.File;

/**
 * Refactored UnifiedServer - main server class
 * Handles HTTP and WebSocket connections with proper protocol support
 */
public class UnifiedServerRefactored {
    
    public static void main(String[] args) throws Exception {
        int port = ServerConfig.getPort();
        File uploads = new File(ServerConfig.getUploadsDir());
        if (!uploads.exists()) uploads.mkdirs();
        
        // Initialize admin logging
        AdminLogger.log("INFO", "SYSTEM", "Server starting on port " + port);
        
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            
                            // HTTP codec
                            pipeline.addLast(new HttpServerCodec());
                            pipeline.addLast(new ChunkedWriteHandler());
                            pipeline.addLast(new HttpObjectAggregator(ServerConfig.MAX_MESSAGE_SIZE));
                            
                            // WebSocket protocol handler - handles upgrade and protocol
                            pipeline.addLast(new WebSocketServerProtocolHandler("/", null, true));
                            
                            // Custom handler for business logic
                            pipeline.addLast(new UnifiedServerHandler());
                        }
                    });
            
            ChannelFuture future = bootstrap.bind(port).sync();
            AdminLogger.log("INFO", "SYSTEM", "Server started successfully on port " + port);
            System.out.println("Server started on port " + port);
            
            future.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
