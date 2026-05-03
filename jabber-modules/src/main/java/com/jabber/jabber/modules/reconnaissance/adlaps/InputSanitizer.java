package com.jabber.jabber.modules.reconnaissance.adlaps;

import java.util.regex.Pattern;

/**
 * InputSanitizer — Validation logic for the ADLAPS Password module.
 */
public class InputSanitizer {

    private static final Pattern DOMAIN_PATTERN =
        Pattern.compile("^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$");
    
    private static final Pattern BASE_DN_PATTERN =
        Pattern.compile("^(?:[a-zA-Z]+=[^,]+(?:,[a-zA-Z]+=[^,]+)*)?$");

    public static String validateTarget(String input) {
        if (input == null || input.isBlank()) return "";
        String target = input.trim();
        if (target.length() > 253) throw new IllegalArgumentException("Target too long");
        if (!target.matches("^[a-zA-Z0-9.\\-/]+$")) {
            throw new IllegalArgumentException("Invalid target format: " + target);
        }
        return target;
    }

    public static String validateDomain(String input) {
        if (input == null || input.isBlank()) return "";
        String domain = input.trim().toLowerCase();
        if (!DOMAIN_PATTERN.matcher(domain).matches()) {
            throw new IllegalArgumentException("Invalid domain: " + domain);
        }
        return domain;
    }

    public static String validateBaseDn(String input) {
        if (input == null || input.isBlank()) return "";
        String dn = input.trim();
        if (!BASE_DN_PATTERN.matcher(dn).matches()) {
            throw new IllegalArgumentException("Invalid Base DN format: " + dn);
        }
        return dn;
    }

    public static String validateUsername(String input) {
        if (input == null || input.isBlank()) return "";
        String username = input.trim();
        if (username.matches(".*[;&|`$\n].*")) {
            throw new IllegalArgumentException("Invalid characters in username");
        }
        return username;
    }

    public static String validatePassword(String input) {
        if (input == null) return "";
        return input.trim();
    }
}
