package com.jabber.jrts.data.model;

/**
 * Risk classification for JRTS modules, matching the KnowledgeBase triage levels.
 */
public enum RiskLevel {
    LOW("Low", "#4caf50"),
    MEDIUM("Medium", "#ff9800"),
    HIGH("High", "#ff5722"),
    CRITICAL("Critical", "#f44336");

    private final String label;
    private final String color;

    RiskLevel(String label, String color) {
        this.label = label;
        this.color = color;
    }

    public String getLabel() { return label; }
    public String getColor() { return color; }
}
