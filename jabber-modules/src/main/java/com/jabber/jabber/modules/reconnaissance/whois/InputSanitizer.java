package com.jabber.jabber.modules.reconnaissance.whois;

import java.util.regex.Pattern;

/**
 * InputSanitizer — Validation logic for the Whois module.
 */
public class InputSanitizer {

    private static final Pattern DOMAIN_IP_PATTERN =
        Pattern.compile("^[a-zA-Z0-9.\\-/]+$");

    private static final Pattern ASN_PATTERN =
        Pattern.compile("^(?i)AS\\d{1,10}$");
        
    private static final Pattern HANDLE_PATTERN =
        Pattern.compile("^[a-zA-Z0-9._\\-]+$");

    private static final Pattern EMAIL_PATTERN =
        Pattern.compile("^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");

    public static String validateTarget(String input) {
        if (input == null || input.isBlank()) return "";
        String target = input.trim();
        if (target.length() > 253) throw new IllegalArgumentException("Target too long");
        if (!DOMAIN_IP_PATTERN.matcher(target).matches()) {
            throw new IllegalArgumentException("Invalid target format: " + target);
        }
        return target;
    }

    public static String validateAsn(String input) {
        if (input == null || input.isBlank()) return "";
        String asn = input.trim().toUpperCase();
        if (!ASN_PATTERN.matcher(asn).matches()) {
            throw new IllegalArgumentException("Invalid ASN format (e.g. AS13335): " + asn);
        }
        return asn;
    }

    public static String validateHandle(String input) {
        if (input == null || input.isBlank()) return "";
        String handle = input.trim();
        if (handle.length() > 100) throw new IllegalArgumentException("Handle too long");
        if (!HANDLE_PATTERN.matcher(handle).matches()) {
            throw new IllegalArgumentException("Invalid handle format: " + handle);
        }
        return handle;
    }

    public static String validateEmail(String input) {
        if (input == null || input.isBlank()) return "";
        String email = input.trim();
        if (email.length() > 254) throw new IllegalArgumentException("Email too long");
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }
        return email;
    }
}
