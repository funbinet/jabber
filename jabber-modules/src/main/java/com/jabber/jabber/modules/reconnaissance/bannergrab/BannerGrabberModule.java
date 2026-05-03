package com.jabber.jabber.modules.reconnaissance.bannergrab;

import com.jabber.jabber.data.model.Category;
import com.jabber.jabber.data.model.JABBERModule;
import com.jabber.jabber.data.model.JABBERModuleInterface;
import com.jabber.jabber.data.model.ModuleInputField;
import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.RiskLevel;
import com.jabber.jabber.data.model.TaskContext;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.jabber.jabber.data.model.ToolingModule;

@JABBERModule(
    id = "recon-banner-grab",
    name = "Stack Identity Mapper",
    description = "Total technology stack identification, infrastructure mapping, banner grabbing, and vulnerability correlation via multi-tool orchestration.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "nmap, whatweb, searchsploit, httpx, dnsx, subfinder, dig, whois",
    author = "JABBER"
)
public class BannerGrabberModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;

    public BannerGrabberModule() {
        this(new ToolManager());
    }

    public BannerGrabberModule(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    @Override
    public List<Map<String, Object>> getToolStatuses() {
        return toolManager.getToolStatuses();
    }

    @Override
    public List<Map<String, Object>> getToolStatusesForMode(String mode) {
        List<Map<String, Object>> allTools = toolManager.getToolStatuses();
        List<String> allowedTools;

        if ("FINGER".equalsIgnoreCase(mode)) {
            allowedTools = List.of("nmap", "whatweb", "searchsploit", "httpx", "dnsx", "dig", "whois", "subfinder");
        } else if ("INFRA".equalsIgnoreCase(mode)) {
            allowedTools = List.of("subfinder", "dnsx", "whois", "dig", "httpx");
        } else {
            return allTools; // fallback
        }

        return allTools.stream()
                .filter(t -> allowedTools.contains(t.get("id")))
                .toList();
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

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // ──── Mode Selector ────
            ModuleInputField.select("mode", "Execution Mode", List.of("FINGER", "INFRA"))
                .required()
                .defaultValue("FINGER")
                .group("Mode")
                .helpText("FINGER: Total technology stack identification and vulnerability correlation. INFRA: Full infrastructure mapping and attribution."),

            // ──── FINGER Mode Inputs ────
            ModuleInputField.text("target", "Target Host / IP")
                .placeholder("10.10.10.5 or app.contoso.local")
                .required()
                .group("Target")
                .modes("FINGER")
                .helpText("IP address or hostname for banner grabbing and service fingerprinting."),

            ModuleInputField.text("domain", "Domain")
                .placeholder("contoso.local")
                .group("Target")
                .modes("FINGER", "INFRA")
                .helpText("Domain for DNS context, subdomain discovery, and WHOIS attribution."),

            // ──── INFRA Mode Input ────
            // INFRA only needs domain (already declared above with both modes)

            // ──── Execution Tuning ────
            ModuleInputField.text("timeout", "Tool Timeout (seconds)")
                .placeholder("120")
                .defaultValue("120")
                .group("Execution")
                .helpText("Maximum time in seconds for each individual tool execution.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        BannerGrabberEngine engine = new BannerGrabberEngine(toolManager);
        return CompletableFuture.supplyAsync(() -> engine.execute(input, ctx));
    }
}