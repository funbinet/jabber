package com.jabber.jrts.data.model;

import java.time.Instant;
import java.util.*;

/**
 * Core domain model representing a module's metadata and descriptor.
 * Serialized to JSON for the Electron frontend.
 */
public class ModuleDescriptor {
    private String id;
    private String name;
    private String description;
    private Category category;
    private RiskLevel riskLevel;
    private String version;
    private String author;
    private String sourceRef; // Original frags script name
    private List<String> capabilities;
    private List<ModuleInputField> inputSchema;
    private List<String> outputFormats;

    public ModuleDescriptor() {}

    public ModuleDescriptor(String id, String name, String description,
                            Category category, RiskLevel riskLevel, String version) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.category = category;
        this.riskLevel = riskLevel;
        this.version = version;
        this.capabilities = new ArrayList<>();
        this.inputSchema = new ArrayList<>();
        this.outputFormats = List.of("JSON", "TXT");
    }

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Category getCategory() { return category; }
    public void setCategory(Category category) { this.category = category; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getAuthor() { return author; }
    public void setAuthor(String author) { this.author = author; }
    public String getSourceRef() { return sourceRef; }
    public void setSourceRef(String sourceRef) { this.sourceRef = sourceRef; }
    public List<String> getCapabilities() { return capabilities; }
    public void setCapabilities(List<String> capabilities) { this.capabilities = capabilities; }
    public List<ModuleInputField> getInputSchema() { return inputSchema; }
    public void setInputSchema(List<ModuleInputField> inputSchema) { this.inputSchema = inputSchema; }
    public List<String> getOutputFormats() { return outputFormats; }
    public void setOutputFormats(List<String> outputFormats) { this.outputFormats = outputFormats; }
}
