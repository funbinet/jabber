package com.jabber.jabber.modules.reconnaissance.portscan;

import java.util.regex.Pattern;

/**
 * InputSanitizer — Mode-aware validation logic for the Port Scanner module.
 *
 * Validates IPs, CIDRs, port ranges, rates, and network interfaces before
 * they reach ProcessBuilder command construction.
 */
public class InputSanitizer {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern CIDR_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$");
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$");
    private static final Pattern PORT_SPEC_PATTERN = Pattern.compile("^[0-9,\\- ]+$");
    private static final Pattern INTERFACE_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /**
     * Validate a target (IP, CIDR, IP range, or hostname). Throws on invalid input.
     */
    public static String validateTarget(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Target cannot be empty");
        }
        String target = input.trim();
        if (target.length() > 253) {
            throw new IllegalArgumentException("Target too long: " + target.length() + " characters (max 253)");
        }
        // Allow comma-separated targets
        for (String part : target.split(",")) {
            String p = part.trim();
            if (p.isEmpty()) continue;
            if (!IPV4_PATTERN.matcher(p).matches()
                && !CIDR_PATTERN.matcher(p).matches()
                && !HOSTNAME_PATTERN.matcher(p).matches()
                && !p.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}-\\d{1,3}$")) {
                throw new IllegalArgumentException("Invalid target: " + p);
            }
        }
        return target;
    }

    /**
     * Validate a CIDR notation specifically. Throws on invalid input.
     */
    public static String validateCidr(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("CIDR cannot be empty");
        }
        String cidr = input.trim();
        if (!CIDR_PATTERN.matcher(cidr).matches() && !IPV4_PATTERN.matcher(cidr).matches()) {
            throw new IllegalArgumentException("Invalid CIDR or IP: " + cidr);
        }
        return cidr;
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
     * Validate a network interface name.
     */
    public static String validateInterface(String input) {
        if (input == null || input.isBlank()) return "";
        String iface = input.trim();
        if (!INTERFACE_PATTERN.matcher(iface).matches()) {
            throw new IllegalArgumentException("Invalid interface name: " + iface);
        }
        return iface;
    }

    /**
     * Sanitize a filename for safe filesystem use.
     */
    public static String sanitizeFilename(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
