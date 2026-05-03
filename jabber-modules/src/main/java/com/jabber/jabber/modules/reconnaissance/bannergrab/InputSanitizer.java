package com.jabber.jabber.modules.reconnaissance.bannergrab;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * InputSanitizer — Mode-aware validation logic for the Banner Grabber module.
 *
 * Validates IPs, domains, hostnames, ports, and file paths before they reach
 * ProcessBuilder command construction. Prevents injection and malformed inputs.
 */
public class InputSanitizer {

    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$");
    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,}$");
    private static final Pattern PORT_SPEC_PATTERN = Pattern.compile("^[0-9,\\- ]+$");

    /**
     * Validate a hostname or IP address. Throws on invalid input.
     */
    public static String validateHostname(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Hostname cannot be empty");
        }
        String host = input.trim();
        if (host.length() > 253) {
            throw new IllegalArgumentException("Hostname too long: " + host.length() + " characters (max 253)");
        }
        if (!HOSTNAME_PATTERN.matcher(host).matches() && !IPV4_PATTERN.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid hostname or IP: " + host);
        }
        return host;
    }

    /**
     * Validate a domain name. Throws on invalid input.
     */
    public static String validateDomain(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Domain cannot be empty");
        }
        String domain = input.trim().toLowerCase();
        if (!DOMAIN_PATTERN.matcher(domain).matches() && !IPV4_PATTERN.matcher(domain).matches()) {
            throw new IllegalArgumentException("Invalid domain: " + domain);
        }
        return domain;
    }

    /**
     * Validate a URL, prepending http:// if no scheme is present.
     */
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

    /**
     * Validate an integer within bounds, returning defaultValue for empty/malformed input.
     */
    public static int validateInt(String input, int min, int max, int defaultValue) {
        if (input == null || input.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            int val = Integer.parseInt(input.trim());
            return Math.max(min, Math.min(val, max));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Validate a port specification (e.g., "80,443,1000-2000").
     */
    public static String validatePortSpec(String input) {
        if (input == null || input.isBlank()) return "";
        if (!PORT_SPEC_PATTERN.matcher(input.trim()).matches()) {
            throw new IllegalArgumentException("Invalid port specification: " + input);
        }
        return input.trim();
    }

    /**
     * Sanitize a filename for safe filesystem use.
     */
    public static String sanitizeFilename(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /**
     * Escape a string for safe shell argument usage.
     * Note: ProcessBuilder doesn't use shell interpretation, so this is primarily
     * a defense-in-depth measure for logging and record keeping.
     */
    public static String escapeShellArg(String input) {
        if (input == null) return "";
        return input.replace("'", "'\\''");
    }
}
