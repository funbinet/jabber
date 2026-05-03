package com.jabber.jabber.modules.reconnaissance.crawler;

import com.jabber.jabber.data.model.Category;
import com.jabber.jabber.data.model.JABBERModule;
import com.jabber.jabber.data.model.JABBERModuleInterface;
import com.jabber.jabber.data.model.ModuleInputField;
import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;
import com.jabber.jabber.data.model.ToolingModule;
import com.jabber.jabber.data.model.RiskLevel;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * WebCrawlerModule — JABBER V 5.5.0 Production-Grade Module.
 *
 * Implements the UNO blueprint for multi-tool web crawling and infrastructure
 * discovery.
 * Supports SURVEY and DEEP execution modes.
 */
@JABBERModule(id = "recon-web-crawler", name = "Web Asset Crawler", description = "Production-grade web application crawling, historical URL analysis, and infrastructure mapping via multi-tool orchestration.", category = Category.RECONNAISSANCE, riskLevel = RiskLevel.LOW, sourceRef = "gospider, katana, httpx, waybackurls, gau, subfinder, dnsx, whois", author = "JABBER")
public class WebCrawlerModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;

    public WebCrawlerModule() {
        this(new ToolManager());
    }

    public WebCrawlerModule(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    @Override
    public List<Map<String, Object>> getToolStatuses() {
        return toolManager.getToolStatuses();
    }

    @Override
    public List<Map<String, Object>> getToolStatusesForMode(String mode) {
        List<Map<String, Object>> allTools = toolManager.getToolStatuses();
        List<String> allowedTools = "SURVEY".equalsIgnoreCase(mode)
                ? List.of("subfinder", "dnsx", "httpx", "gospider", "whois")
                : List.of("katana", "waybackurls", "gau", "httpx", "dnsx");

        return allTools.stream()
                .filter(t -> allowedTools.contains(t.get("id")))
                .toList();
    }

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
                ModuleInputField.select("mode", "Execution Mode", List.of("SURVEY", "DEEP"))
                        .required()
                        .defaultValue("SURVEY")
                        .group("Strategy")
                        .helpText("SURVEY: Fast infra discovery. DEEP: Exhaustive historical analysis."),

                ModuleInputField.text("url", "Target URL")
                        .required()
                        .placeholder("https://example.com")
                        .group("Target")
                        .modes("SURVEY", "DEEP"),

                ModuleInputField.text("domain", "Target Domain")
                        .placeholder("example.com")
                        .group("Target")
                        .modes("SURVEY", "DEEP"),

                ModuleInputField.text("depth", "Crawl Depth")
                        .defaultValue("2")
                        .placeholder("2")
                        .group("Tuning")
                        .modes("SURVEY", "DEEP"),

                ModuleInputField.text("timeout", "Timeout (sec)")
                        .defaultValue("300")
                        .placeholder("300")
                        .group("Execution")
                        .modes("SURVEY", "DEEP"));
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        WebCrawlerEngine engine = new WebCrawlerEngine(toolManager);
        return CompletableFuture.supplyAsync(() -> engine.execute(input, ctx));
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
