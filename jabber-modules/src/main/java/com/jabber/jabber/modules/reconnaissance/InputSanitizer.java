package com.jabber.jabber.modules.reconnaissance;

import java.net.URI;
import java.net.URISyntaxException;

public class InputSanitizer {

    public static String validateUrl(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Target URL cannot be empty");
        }
        
        String url = input.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        try {
            URI uri = new URI(url);
            if (uri.getHost() == null) {
                throw new IllegalArgumentException("Invalid URL: missing host");
            }
            return url;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Malformed target URL: " + e.getMessage());
        }
    }

    public static int validateInt(String input, int min, int max, int defaultValue) {
        if (input == null || input.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            int val = Integer.parseInt(input.trim());
            if (val < min) return min;
            if (val > max) return max;
            return val;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public static String sanitizeFilename(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9.-]", "_");
    }

    public static String escapeShellArg(String input) {
        if (input == null) return "";
        return input.replace("'", "'\\''");
    }

    public static String validatePortSpec(String input) {
        if (input == null || input.isBlank()) return "";
        // Basic check for ports/ranges like 80,443,1000-2000
        if (!input.matches("[0-9,-]+")) {
            throw new IllegalArgumentException("Invalid port specification: " + input);
        }
        return input.trim();
    }

    public static String validateHostname(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Hostname cannot be empty");
        }
        String host = input.trim();
        // Simple hostname regex
        if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            throw new IllegalArgumentException("Invalid hostname: " + host);
        }
        return host;
    }
}
