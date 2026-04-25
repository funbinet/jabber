package com.jabber.jrts.core.terminal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final TerminalWebsocketHandler terminalWebsocketHandler;

    @Autowired
    public WebSocketConfig(TerminalWebsocketHandler terminalWebsocketHandler) {
        this.terminalWebsocketHandler = terminalWebsocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(terminalWebsocketHandler, "/api/terminal/ws")
                .setAllowedOrigins("*");
    }
}
