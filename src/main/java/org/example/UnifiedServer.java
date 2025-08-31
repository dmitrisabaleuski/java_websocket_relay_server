package org.example;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrameAggregator;
import io.netty.handler.stream.ChunkedWriteHandler;
import org.example.handlers.UnifiedServerHandler;
import org.example.utils.ServerConfig;

import java.io.File;

/**
 * Main HomeCloud Server class
 * Handles server bootstrap and initialization
 */
public class UnifiedServer {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        File uploads = new File(ServerConfig.UPLOADS_DIR);
        if (!uploads.exists()) uploads.mkdirs();
        
        System.out.println("[SERVER] Starting HomeCloud Server on port " + port);

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline pipeline = ch.pipeline();
                            pipeline.addLast(new HttpServerCodec());
                            pipeline.addLast(new HttpObjectAggregator(64 * 1024 * 1024));
                            pipeline.addLast(new WebSocketServerProtocolHandler("/", null, true, 64 * 1024 * 1024));
                            pipeline.addLast(new WebSocketFrameAggregator(64 * 1024 * 1024));
                            pipeline.addLast(new ChunkedWriteHandler());
                            pipeline.addLast(new UnifiedServerHandler());
                        }
                    });

            System.out.println("[SERVER] Netty server started on port " + port);
            
            // Start heartbeat timer
            org.example.utils.HeartbeatManager.startHeartbeatTimer();
            System.out.println("[SERVER] Heartbeat timer started");

            b.bind(port).sync().channel().closeFuture().sync();
        } finally {
            org.example.utils.HeartbeatManager.stopHeartbeatTimer();
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
