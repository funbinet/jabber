package com.jabber.jrts.data.model;

import java.util.*;

/**
 * Represents a module input field definition.
 * Used to dynamically generate UI forms for each module.
 */
public class ModuleInputField {
    private String name;
    private String label;
    private String type; // "text", "password", "select", "checkbox", "number", "textarea", "file"
    private String placeholder;
    private String defaultValue;
    private boolean required;
    private List<String> options; // For "select" type
    private List<String> modes; // Optional mode binding for dynamic field visibility
    private String helpText;
    private String group; // Group label for organizing fields

    public ModuleInputField() {}

    public ModuleInputField(String name, String label, String type, boolean required) {
        this.name = name;
        this.label = label;
        this.type = type;
        this.required = required;
    }

    // Builder pattern
    public static ModuleInputField text(String name, String label) {
        return new ModuleInputField(name, label, "text", false);
    }

    public static ModuleInputField password(String name, String label) {
        return new ModuleInputField(name, label, "password", false);
    }

    public static ModuleInputField select(String name, String label, List<String> options) {
        ModuleInputField f = new ModuleInputField(name, label, "select", false);
        f.setOptions(options);
        return f;
    }

    public static ModuleInputField checkbox(String name, String label) {
        return new ModuleInputField(name, label, "checkbox", false);
    }

    public static ModuleInputField textarea(String name, String label) {
        return new ModuleInputField(name, label, "textarea", false);
    }

    public ModuleInputField required() { this.required = true; return this; }
    public ModuleInputField placeholder(String p) { this.placeholder = p; return this; }
    public ModuleInputField defaultValue(String d) { this.defaultValue = d; return this; }
    public ModuleInputField helpText(String h) { this.helpText = h; return this; }
    public ModuleInputField group(String g) { this.group = g; return this; }
    public ModuleInputField modes(String... m) {
        if (m == null || m.length == 0) {
            this.modes = null;
        } else {
            this.modes = List.of(m);
        }
        return this;
    }
    public ModuleInputField modes(List<String> m) {
        this.modes = m == null ? null : List.copyOf(m);
        return this;
    }
    public ModuleInputField build() { return this; }

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getPlaceholder() { return placeholder; }
    public void setPlaceholder(String placeholder) { this.placeholder = placeholder; }
    public String getDefaultValue() { return defaultValue; }
    public void setDefaultValue(String defaultValue) { this.defaultValue = defaultValue; }
    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }
    public List<String> getOptions() { return options; }
    public void setOptions(List<String> options) { this.options = options; }
    public List<String> getModes() { return modes; }
    public void setModes(List<String> modes) { this.modes = modes; }
    public String getHelpText() { return helpText; }
    public void setHelpText(String helpText) { this.helpText = helpText; }
    public String getGroup() { return group; }
    public void setGroup(String group) { this.group = group; }
}
