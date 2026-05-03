package com.jabber.jabber.modules.reconnaissance.emailverify;

import java.util.regex.Pattern;

/**
 * InputSanitizer — Validation logic for the EmailVerifier module.
 */
public class InputSanitizer {

    private static final Pattern DOMAIN_PATTERN =
        Pattern.compile("^[a-zA-Z0-9.\\-/]+$");

    private static final Pattern EMAIL_PATTERN =
        Pattern.compile("^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");

    private static final Pattern USERNAME_PATTERN =
        Pattern.compile("^[a-zA-Z0-9._\\-]+$");

    public static String validateDomain(String input) {
        if (input == null || input.isBlank()) return "";
        String domain = input.trim();
        if (domain.length() > 253) throw new IllegalArgumentException("Domain too long");
        if (!DOMAIN_PATTERN.matcher(domain).matches()) {
            throw new IllegalArgumentException("Invalid domain format: " + domain);
        }
        return domain;
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

    public static String validateUsername(String input) {
        if (input == null || input.isBlank()) return "";
        String username = input.trim();
        if (username.length() > 100) throw new IllegalArgumentException("Username too long");
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException("Invalid username format: " + username);
        }
        return username;
    }
}
