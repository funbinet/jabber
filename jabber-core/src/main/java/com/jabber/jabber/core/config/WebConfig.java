package com.jabber.jabber.core.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;
import java.io.IOException;

/**
 * Web configuration for serving the React SPA frontend.
 * 
 * In production (installed via .deb), static files live in /opt/jabber/ui/dist/.
 * All non-API, non-file routes fall back to index.html for client-side routing.
 * 
 * Created by Funbinet (dancan.tech)
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("file:/opt/jabber/ui/dist/", "classpath:/static/")
                .resourceChain(true)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location) throws IOException {
                        Resource requested = location.createRelative(resourcePath);
                        // If the requested file exists, serve it
                        if (requested.exists() && requested.isReadable()) {
                            return requested;
                        }
                        // Otherwise, if this is NOT an API call, serve index.html (SPA fallback)
                        if (!resourcePath.startsWith("api/") && !resourcePath.startsWith("h2-console")) {
                            // Try filesystem first (installed), then classpath (dev)
                            Resource fsIndex = new FileSystemResource("/opt/jabber/ui/dist/index.html");
                            if (fsIndex.exists()) {
                                return fsIndex;
                            }
                            Resource cpIndex = new ClassPathResource("/static/index.html");
                            if (cpIndex.exists()) {
                                return cpIndex;
                            }
                        }
                        return null;
                    }
                });
    }
}
