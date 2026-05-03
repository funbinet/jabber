package com.jabber.jabber.modules.reconnaissance.adcomputer;

import com.jabber.jabber.data.model.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * ADComputerModule — JABBER V 5.5.0 Module for Active Directory Computer Enumeration.
 *
 * Implements the ToolingModule interface for dynamic binary tracking.
 */
@JABBERModule(
    id = "recon-ad-computers",
    name = "AD Computer Enumerator",
    description = "Passive and active enumeration of Active Directory domain computers via ldapsearch, crackmapexec, rpcclient, and nmap.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "Blueprint 10 - JABBER V 5.5.0",
    author = "JABBER"
)
public class ADComputerModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;
    private final ADComputerEngine engine;

    public ADComputerModule() {
        this.toolManager = new ToolManager();
        this.engine = new ADComputerEngine(this.toolManager);
    }

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("SURVEY", "ACTIVE"))
                .required()
                .defaultValue("SURVEY")
                .group("Pipeline")
                .helpText("SURVEY = Unauthenticated enumeration via LDAP and Null Sessions. ACTIVE = Authenticated extraction and SMB validation."),

            ModuleInputField.text("dc", "Domain Controller (DC)")
                .required()
                .placeholder("10.10.10.10 or dc01.corp.local")
                .group("Target")
                .helpText("IP or FQDN of the primary Domain Controller."),
                
            ModuleInputField.text("domain", "Domain Name")
                .required()
                .placeholder("corp.local")
                .group("Target")
                .helpText("The Active Directory domain name."),

            ModuleInputField.text("base_dn", "Base DN")
                .placeholder("DC=corp,DC=local")
                .group("Target")
                .helpText("Base Distinguished Name for LDAP queries. Leave blank to auto-detect (if possible)."),

            ModuleInputField.text("user", "Username")
                .placeholder("operator or corp.local\\operator")
                .group("Authentication")
                .modes("ACTIVE")
                .helpText("Required for ACTIVE mode. Domain user."),

            ModuleInputField.password("pass", "Password")
                .group("Authentication")
                .modes("ACTIVE")
                .helpText("Required for ACTIVE mode. User password.")
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
