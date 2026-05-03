package com.jabber.jabber.modules.reconnaissance.whois;

import com.jabber.jabber.data.model.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * WhoisModule — Hardcore OSINT and Infrastructure Mapping Engine.
 */
@JABBERModule(
    id = "recon-whois",
    name = "Domain Attribution Mapper",
    description = "Ultimate tier-1 OSINT engine mapping internet exposures, corporate acquisitions, BGP routes, and social media personas.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "Blueprint 5 - JABBER V 5.5.0 Hardcore",
    author = "JABBER"
)
public class WhoisModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;
    private final WhoisEngine engine;

    public WhoisModule() {
        this.toolManager = new ToolManager();
        this.engine = new WhoisEngine(this.toolManager);
    }

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("RECO", "ASST", "BGPR", "CORP", "PERS", "BRCH"))
                .required()
                .defaultValue("RECO")
                .group("Pipeline")
                .helpText("RECO=Base, ASST=Neighbors, BGPR=ASN Sweep, CORP=Acquisition Hunt, PERS=Social Media Hunt, BRCH=Data Leak Hunt"),

            ModuleInputField.text("target", "Target Domain/IP")
                .placeholder("example.com or 10.10.10.10")
                .group("Target")
                .modes("RECO", "ASST", "CORP"),

            ModuleInputField.text("cidr", "Target CIDR Range")
                .placeholder("10.10.10.0/24")
                .group("Target")
                .modes("ASST"),

            ModuleInputField.text("asn", "Autonomous System Number (ASN)")
                .placeholder("AS13335")
                .group("Target")
                .modes("BGPR"),

            ModuleInputField.text("handle", "Social Media Username / Handle")
                .placeholder("johndoe123")
                .group("Target")
                .modes("PERS")
                .helpText("Hunts this exact username across thousands of global platforms using Sherlock and Maigret."),

            ModuleInputField.text("email", "Target Email Address")
                .placeholder("target@example.com")
                .group("Target")
                .modes("BRCH")
                .helpText("Examine this email against breach databases and account registration forms.")
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
