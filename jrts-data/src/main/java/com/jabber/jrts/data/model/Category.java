package com.jabber.jrts.data.model;

/**
 * Attack lifecycle categories for the JRTS side navigation.
 * Each category maps to a section in the red teaming workflow.
 */
public enum Category {
    RECONNAISSANCE("Reconnaissance", "recon", "Intelligence & Planning", 1),
    VULNERABILITY_SCANNING("Vulnerability Scanning", "vulnscan", "Intelligence & Planning", 2),
    SOCIAL_ENGINEERING("Social Engineering", "social", "Intelligence & Planning", 3),
    FORENSICS("Forensics", "forensics", "Intelligence & Planning", 4),

    EXPLOITATION("Exploitation", "exploit", "Access & Penetration", 5),
    WEB_ASSESSMENT("Web Assessment", "webapp", "Access & Penetration", 6),
    WIRELESS_HACKING("Wireless Hacking", "wireless", "Access & Penetration", 7),
    NETWORK_ATTACK_DEFENSE("Network Attack & Defense", "network", "Access & Penetration", 8),

    PRIVILEGE_ESCALATION("Privilege Escalation", "privesc", "Privilege & Identity", 9),
    LATERAL_MOVEMENT("Lateral Movement", "lateral", "Privilege & Identity", 10),
    CREDENTIAL_ACCESS("Credential Access", "credaccess", "Privilege & Identity", 11),
    PASSWORD_CRACKING("Password Cracking", "passcrack", "Privilege & Identity", 12),

    PAYLOAD_CREATION("Payload Creation & Injection", "payload", "Operations & Assets", 13),
    CRYPTO_OPERATIONS("Cryptographic Operations", "crypto", "Operations & Assets", 14),
    C2_PERSISTENCE("C2 Server & Persistence", "c2", "Operations & Assets", 15),
    AD_MANAGEMENT("AD Management", "admanage", "Operations & Assets", 16),

    SAVED_CREDENTIALS("Saved Credentials", "savedcreds", "Data & Utilities", 17),
    REPORTS("Reports", "reports", "Data & Utilities", 18),
    UTILITIES("Utilities", "util", "Data & Utilities", 19),
    PHONE_ENUMERATION("Phone Enumeration", "phoneenum", "Data & Utilities", 20);

    private final String displayName;
    private final String slug;
    private final String group;
    private final int sortOrder;

    Category(String displayName, String slug, String group, int sortOrder) {
        this.displayName = displayName;
        this.slug = slug;
        this.group = group;
        this.sortOrder = sortOrder;
    }

    public String getDisplayName() { return displayName; }
    public String getSlug() { return slug; }
    public String getGroup() { return group; }
    public int getSortOrder() { return sortOrder; }
}
