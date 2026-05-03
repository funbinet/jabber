package com.jabber.jabber.modules.reconnaissance.dnsenum;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(
    id = "recon-dns-enum",
    name = "DNS Infrastructure Mapper",
    description = "Production-grade DNS reconnaissance suite. Performs passive/active discovery, record resolution, and zone transfers using high-fidelity tools.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "dnsx/subfinder/dig",
    author = "JABBER"
)
public class DNSEnumeratorModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager = new ToolManager();
    private final DNSEnumeratorEngine engine = new DNSEnumeratorEngine(toolManager);

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("SRVY", "BRUT"))
                .required()
                .defaultValue("SRVY")
                .helpText("SRVY: Passive/Light active mapping. BRUT: Intensive subdomain brute-forcing."),
            
            ModuleInputField.text("domain", "Target Domain")
                .placeholder("example.com")
                .required()
                .helpText("Primary target domain for DNS enumeration."),
            
            ModuleInputField.text("wordlist", "Brute-force Wordlist")
                .placeholder("/path/to/wordlist.txt")
                .modes("BRUT")
                .helpText("Custom wordlist for subdomain brute-forcing.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> engine.execute(input, ctx));
    }

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
