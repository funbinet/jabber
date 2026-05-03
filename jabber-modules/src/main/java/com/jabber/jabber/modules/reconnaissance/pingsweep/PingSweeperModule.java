package com.jabber.jabber.modules.reconnaissance.pingsweep;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(
    id = "recon-pingsweep",
    name = "Elite Ping Sweeper",
    description = "Elite multi-tool network discovery suite. Orchestrates hping3, masscan, rustscan, netdiscover, and enum4linux for CRITICAL infrastructure mapping and evasion analysis.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.CRITICAL,
    sourceRef = "masscan/hping3/rustscan",
    author = "JABBER"
)
public class PingSweeperModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager = new ToolManager();
    private final PingSweeperEngine engine = new PingSweeperEngine(toolManager);

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("SRVY", "STH", "AGGR", "ADVR"))
                .required()
                .defaultValue("SRVY")
                .helpText("SRVY: Survey. STH: Stealth. AGGR: Aggressive (Masscan). ADVR: Adversarial (Enum4Linux)."),
            
            ModuleInputField.text("cidr", "Target Range / IP")
                .placeholder("192.168.1.0/24")
                .required()
                .helpText("CIDR notation or single target IP for discovery."),
            
            ModuleInputField.text("target_port", "Specific Port Probe")
                .placeholder("80")
                .modes("STH", "AGGR")
                .helpText("Specific port for SYN/TCP probes or Masscan range."),

            ModuleInputField.checkbox("include_nonresponsive", "Include Silent Hosts")
                .defaultValue("false")
                .helpText("Display hosts that did not respond to any probes.")
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
