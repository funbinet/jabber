package com.jabber.jabber.modules.reconnaissance.emailverify;

import com.jabber.jabber.data.model.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * EmailVerifierModule — Hardcore OSINT and Identity Engine.
 */
@JABBERModule(
    id = "recon-email-verify",
    name = "Mail Intelligence Master",
    description = "Ultimate tier-1 OSINT engine for discovering corporate emails, footprinting identities, and extracting breached credentials.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "Blueprint 6 - JABBER V 5.5.0 Hardcore",
    author = "JABBER"
)
public class EmailVerifierModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;
    private final EmailVerifierEngine engine;

    public EmailVerifierModule() {
        this.toolManager = new ToolManager();
        this.engine = new EmailVerifierEngine(this.toolManager);
    }

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("PROB", "HUNT", "SOCI", "BRCH", "SMTP"))
                .required()
                .defaultValue("PROB")
                .group("Pipeline")
                .helpText("PROB=Domain Scraping, HUNT=Reputation, SOCI=Username Footprint, BRCH=Data Leaks, SMTP=Protocol Probe"),

            ModuleInputField.text("domain", "Target Domain")
                .placeholder("example.com")
                .group("Target")
                .modes("PROB", "SMTP")
                .helpText("Target domain for scraping or SMTP MX resolution."),

            ModuleInputField.text("email", "Target Email Address")
                .placeholder("target@example.com")
                .group("Target")
                .modes("HUNT", "BRCH", "SMTP")
                .helpText("Target email for reputation, breach hunt, or SMTP validation."),

            ModuleInputField.text("username", "Social Media Username / Handle")
                .placeholder("johndoe123")
                .group("Target")
                .modes("SOCI")
                .helpText("Hunts this exact username across thousands of global platforms using Maigret.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> engine.execute(input, ctx));
    }

    // ── ToolingModule Implementation ──

    @Override
    public List<Map<String, Object>> getToolStatuses() {
        return toolManager.getToolStatuses();
    }

    @Override
    public List<Map<String, Object>> getToolStatusesForMode(String mode) {
        return toolManager.getToolStatusesForMode(mode);
    }

    @Override
    public Map<String, Object> downloadTool(String toolId) {
        return toolManager.downloadTool(toolId);
    }

    @Override
    public Map<String, Object> getToolDownloadStatus(String toolId) {
        return toolManager.getToolDownloadStatus(toolId);
    }

    @Override
    public Map<String, Object> deleteTool(String toolId) {
        return toolManager.deleteTool(toolId);
    }
}
