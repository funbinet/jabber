package com.jabber.jabber.modules.reconnaissance.portscan;

import com.jabber.jabber.data.model.Category;
import com.jabber.jabber.data.model.JABBERModule;
import com.jabber.jabber.data.model.JABBERModuleInterface;
import com.jabber.jabber.data.model.ModuleInputField;
import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.RiskLevel;
import com.jabber.jabber.data.model.TaskContext;
import com.jabber.jabber.data.model.ToolingModule;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@JABBERModule(
    id = "recon-portscanner",
    name = "Universal Port Mapper",
    description = "Multi-layered port discovery and service validation via masscan, nmap, httpx, dnsx, and arp-scan orchestration.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "nmap, masscan, arp-scan, dnsx, httpx",
    author = "JABBER"
)
public class PortScannerModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;

    public PortScannerModule() {
        this(new ToolManager());
    }

    public PortScannerModule(ToolManager toolManager) {
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

        if ("ACTIVE".equalsIgnoreCase(mode)) {
            allowedTools = List.of("masscan", "nmap", "httpx", "dnsx", "arp-scan");
        } else if ("SURVEY".equalsIgnoreCase(mode)) {
            allowedTools = List.of("arp-scan", "nmap", "dnsx", "httpx", "masscan");
        } else {
            return allTools;
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
            ModuleInputField.select("mode", "Execution Mode", List.of("ACTIVE", "SURVEY"))
                .required()
                .defaultValue("ACTIVE")
                .group("Mode")
                .helpText("ACTIVE: Multi-layered port discovery and service validation. SURVEY: Passive-first network mapping and host discovery."),

            // ──── ACTIVE Mode Inputs ────
            ModuleInputField.text("target", "Target IP(s) or CIDR")
                .placeholder("192.168.1.10 or 10.0.0.0/24")
                .required()
                .group("Target")
                .modes("ACTIVE")
                .helpText("IP address, CIDR range, or comma-separated targets for port scanning."),

            ModuleInputField.text("ports", "Port Range")
                .placeholder("1-1024, 3389, 8080 (Leave empty for default)")
                .group("Scan Config")
                .modes("ACTIVE")
                .helpText("Comma/dash-separated port specification. Leave empty for top common ports."),

            ModuleInputField.text("rate", "Masscan Rate (pps)")
                .placeholder("1000")
                .defaultValue("1000")
                .group("Scan Config")
                .modes("ACTIVE")
                .helpText("Packets per second for masscan. Higher values are faster but noisier."),

            // ──── SURVEY Mode Inputs ────
            ModuleInputField.text("cidr", "CIDR / Subnet")
                .placeholder("192.168.1.0/24")
                .required()
                .group("Target")
                .modes("SURVEY")
                .helpText("CIDR notation for network mapping and host discovery."),

            ModuleInputField.text("interface", "Network Interface")
                .placeholder("eth0 (optional)")
                .group("Target")
                .modes("SURVEY")
                .helpText("Network interface for arp-scan. Leave empty for default."),

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
        PortScannerEngine engine = new PortScannerEngine(toolManager);
        return CompletableFuture.supplyAsync(() -> engine.execute(input, ctx));
    }
}
