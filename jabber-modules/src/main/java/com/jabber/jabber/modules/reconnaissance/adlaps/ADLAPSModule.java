package com.jabber.jabber.modules.reconnaissance.adlaps;

import com.jabber.jabber.data.model.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * ADLAPSModule — JABBER V 5.5.0 Module for Active Directory LAPS Enumeration.
 */
@JABBERModule(
    id = "recon-ad-laps",
    name = "AD LAPS Auditor",
    description = "Enumerate AD computers with Classic LAPS or Windows LAPS attributes and orchestrate SMB validation via CrackMapExec.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "Blueprint 13 - JABBER V 5.5.0 Hybrid",
    author = "JABBER"
)
public class ADLAPSModule implements JABBERModuleInterface, ToolingModule {

    private final ToolManager toolManager;
    private final ADLAPSEngine engine;

    public ADLAPSModule() {
        this.toolManager = new ToolManager();
        this.engine = new ADLAPSEngine(this.toolManager);
    }

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of("EXTRACT", "VAL"))
                .required()
                .defaultValue("EXTRACT")
                .group("Pipeline")
                .helpText("EXTRACT = JNDI retrieval and initial validation. VAL = Widespread range validation of retrieved credentials."),

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
                .modes("EXTRACT")
                .helpText("Base DN for LDAP queries. Leave blank to auto-detect from RootDSE."),
                
            ModuleInputField.text("target_range", "Target Range")
                .placeholder("10.10.10.0/24")
                .group("Target")
                .modes("VAL")
                .helpText("CIDR range for validation testing (VAL mode)."),

            ModuleInputField.text("user", "Username")
                .placeholder("operator or corp.local\\operator")
                .group("Authentication")
                .helpText("Domain user with privileges to read LAPS attributes."),

            ModuleInputField.password("pass", "Password")
                .group("Authentication")
                .helpText("Domain user password.")
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
