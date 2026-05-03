package com.jabber.jabber.modules.reconnaissance.pingsweep;

import java.util.*;
import java.util.regex.Pattern;

/**
 * InputSanitizer — Secure validation for CIDR and network targets.
 */
public class InputSanitizer {

    private static final Pattern CIDR_PATTERN = 
        Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$");
        
    private static final Pattern IP_PATTERN = 
        Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}$");

    public static List<String> validate(String mode, Map<String, String> input) {
        List<String> errors = new ArrayList<>();

        String cidr = input.get("cidr");
        if (cidr == null || cidr.isBlank()) {
            errors.add("CIDR range or target IP is required.");
        } else {
            String trimmed = cidr.trim();
            if (!CIDR_PATTERN.matcher(trimmed).matches() && !IP_PATTERN.matcher(trimmed).matches()) {
                errors.add("Invalid CIDR/IP format (e.g. 192.168.1.0/24 or 10.0.0.1)");
            }
        }

        if ("AGGR".equalsIgnoreCase(mode) || "ADVR".equalsIgnoreCase(mode)) {
            String port = input.get("target_port");
            if (port != null && !port.isBlank()) {
                try {
                    int p = Integer.parseInt(port.trim());
                    if (p < 1 || p > 65535) errors.add("Target port must be between 1 and 65535.");
                } catch (NumberFormatException e) {
                    errors.add("Invalid port number.");
                }
            }
        }

        return errors;
    }

    public static String sanitizeTarget(String target) {
        if (target == null) return "";
        return target.trim().replaceAll("[^0-9./a-zA-Z-]", "");
    }
}
