package com.jabber.jabber.modules.reconnaissance.dnsenum;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class InputSanitizer {
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+$");

    public static List<String> validate(String mode, Map<String, String> input) {
        List<String> errors = new ArrayList<>();
        String domain = input.get("domain");
        if (domain == null || domain.isBlank()) {
            errors.add("Target domain is required.");
        } else if (!DOMAIN_PATTERN.matcher(domain.trim()).matches()) {
            errors.add("Invalid domain format.");
        }

        if ("BRUTE".equalsIgnoreCase(mode)) {
            String wordlist = input.get("wordlist");
            if (wordlist != null && !wordlist.isBlank()) {
                Path p = Path.of(wordlist);
                if (!Files.exists(p)) {
                    errors.add("Wordlist file does not exist: " + wordlist);
                }
            }
        }
        return errors;
    }

    public static String sanitize(String input) {
        if (input == null) return "";
        return input.trim().replaceAll("[;&|><]", "");
    }
}
