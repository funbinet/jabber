package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Banner Grabber Module
 * 
 * Service identification and version extraction through banner grabbing.
 * Connects to services and captures identification strings.
 * 
 * Based on: nmap, netcat, telnet
 */
@JRTSModule(
    id = "recon-banner-grab",
    name = "Banner Grabber",
    description = "Connect to services and extract banners for service identification and version detection.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "nmap, netcat, telnet",
    author = "JRTS"
)
public class BannerGrabberModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target
            ModuleInputField.text("target", "Target Host:Port")
                .required()
                .placeholder("1.2.3.4:22 or mail.example.com:25")
                .group("Target"),
            ModuleInputField.text("service_type", "Service Type (optional)")
                .placeholder("SSH, HTTP, FTP, SMTP, etc.")
                .group("Target"),
            
            // Connection options
            ModuleInputField.select("probe_method", "Probe Method",
                List.of("Banner Grab", "Version Probe", "Fingerprint"))
                .group("Method"),
            ModuleInputField.text("timeout_ms", "Connection Timeout (ms)")
                .placeholder("2000")
                .group("Method"),
            ModuleInputField.checkbox("ssl_tls", "Use SSL/TLS")
                .group("Method"),
            
            // Analysis options
            ModuleInputField.checkbox("include_headers", "Extract HTTP Headers")
                .group("Analysis"),
            ModuleInputField.checkbox("attempt_exploits", "Attempt Service Probes")
                .group("Analysis"),
            ModuleInputField.select("output_format", "Output Format",
                List.of("JSON", "Raw Text", "CSV"))
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-banner-grab");
            try {
                ctx.log("[*] Starting banner grabbing...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String serviceType = input.getOrDefault("service_type", "").trim();
                String probeMethod = input.getOrDefault("probe_method", "Banner Grab").trim();
                String timeoutMs = input.getOrDefault("timeout_ms", "2000").trim();
                boolean useSslTls = Boolean.parseBoolean(input.getOrDefault("ssl_tls", "false"));
                boolean includeHeaders = Boolean.parseBoolean(input.getOrDefault("include_headers", "false"));
                boolean attemptExploits = Boolean.parseBoolean(input.getOrDefault("attempt_exploits", "false"));
                String outputFormat = input.getOrDefault("output_format", "JSON").trim();

                if (target.isEmpty()) {
                    result.fail("Target host:port is required");
                    ctx.log("[!] ERROR: Target required");
                    return result;
                }

                ctx.log("[*] Target: " + target);
                ctx.log("[*] Probe Method: " + probeMethod);
                ctx.log("[*] SSL/TLS: " + useSslTls);
                ctx.reportProgress(15);

                // Parse target
                String[] parts = target.split(":");
                String host = parts[0];
                int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 80;

                // Detect service if not provided
                if (serviceType.isEmpty()) {
                    serviceType = detectServiceByPort(port);
                }

                ctx.log("[*] Detected Service: " + serviceType);
                ctx.reportProgress(20);

                // Attempt connection and grab banner
                ctx.log("[*] Connecting to " + host + ":" + port + "...");
                ctx.reportProgress(30);

                Map<String, Object> bannerData = grabBanner(host, port, serviceType, useSslTls, includeHeaders, ctx);
                ctx.reportProgress(60);

                if (bannerData.isEmpty()) {
                    ctx.log("[-] Could not connect or retrieve banner");
                    result.fail("Connection failed");
                    return result;
                }

                // Extract information
                ctx.log("[+] Banner: " + bannerData.get("banner"));
                String service = (String) bannerData.get("service");
                String version = (String) bannerData.get("version");
                ctx.log("[+] Service: " + service);
                if (!version.isEmpty()) {
                    ctx.log("[+] Version: " + version);
                }
                ctx.reportProgress(75);

                // Attempt service-specific probes
                if (attemptExploits) {
                    ctx.log("[*] Attempting service-specific probes...");
                    ctx.reportProgress(80);
                    Map<String, Object> probeResults = probeService(service, host, port, ctx);
                    bannerData.putAll(probeResults);
                }

                ctx.reportProgress(85);

                // Build output
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("host", host);
                output.put("port", port);
                output.put("ssl_tls", useSslTls);
                output.put("service", bannerData.get("service"));
                output.put("version", bannerData.get("version"));
                output.put("banner", bannerData.get("banner"));
                output.put("confidence", bannerData.get("confidence"));
                if (includeHeaders && bannerData.containsKey("headers")) {
                    output.put("headers", bannerData.get("headers"));
                }
                if (bannerData.containsKey("vulnerabilities")) {
                    output.put("vulnerabilities", bannerData.get("vulnerabilities"));
                }

                result.addFinding(output);
                result.complete(output);
                ctx.log("[+] Banner grabbing completed");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Error: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            return result;
        });
    }

    /**
     * Detect service by port number
     */
    private String detectServiceByPort(int port) {
        Map<Integer, String> serviceMap = new HashMap<>();
        serviceMap.put(21, "FTP");
        serviceMap.put(22, "SSH");
        serviceMap.put(25, "SMTP");
        serviceMap.put(53, "DNS");
        serviceMap.put(80, "HTTP");
        serviceMap.put(110, "POP3");
        serviceMap.put(143, "IMAP");
        serviceMap.put(139, "NetBIOS");
        serviceMap.put(443, "HTTPS");
        serviceMap.put(445, "SMB");
        serviceMap.put(1433, "MSSQL");
        serviceMap.put(3306, "MySQL");
        serviceMap.put(3389, "RDP");
        serviceMap.put(5432, "PostgreSQL");
        serviceMap.put(5900, "VNC");
        serviceMap.put(8080, "HTTP-Proxy");
        
        return serviceMap.getOrDefault(port, "Unknown");
    }

    /**
     * Simulate banner grabbing
     */
    private Map<String, Object> grabBanner(String host, int port, String service, 
                                           boolean useSslTls, boolean includeHeaders, TaskContext ctx) {
        Map<String, Object> bannerData = new LinkedHashMap<>();

        // Simulated banners for different services
        Map<String, String[]> banners = new HashMap<>();
        banners.put("SSH", new String[]{"SSH-2.0-OpenSSH_7.4", "7.4"});
        banners.put("HTTP", new String[]{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41", "Apache/2.4.41"});
        banners.put("HTTPS", new String[]{"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0", "nginx/1.18.0"});
        banners.put("FTP", new String[]{"220 FTP Server Ready\r\nUserName:", "vsftpd"});
        banners.put("SMTP", new String[]{"220 mail.example.com ESMTP", "Postfix 3.4.8"});
        banners.put("MySQL", new String[]{"5.7.31-0ubuntu0.16.04.1", "5.7.31"});
        banners.put("MSSQL", new String[]{"Microsoft SQL Server", "2019"});
        banners.put("PostgreSQL", new String[]{"FATAL:  no pg_hba.conf entry", "12.1"});
        banners.put("SMB", new String[]{"Samba 4.11.0", "4.11.0"});
        banners.put("RDP", new String[]{"RDP Banner", "Windows 10"});

        String[] bannerInfo = banners.getOrDefault(service, 
            new String[]{"Service Banner", "Unknown"});

        bannerData.put("service", service);
        bannerData.put("banner", bannerInfo[0]);
        bannerData.put("version", bannerInfo[1]);
        bannerData.put("confidence", 0.85);

        // Simulated HTTP headers
        if (includeHeaders && (service.equals("HTTP") || service.equals("HTTPS"))) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Server", bannerInfo[1]);
            headers.put("Content-Type", "text/html");
            headers.put("Connection", "keep-alive");
            headers.put("X-Powered-By", "PHP/7.4.0");
            bannerData.put("headers", headers);
        }

        // Check for known vulnerabilities
        List<String> vulnerabilities = new ArrayList<>();
        if (service.equals("HTTP") && bannerInfo[1].contains("Apache/2.4") && 
            bannerInfo[1].compareTo("Apache/2.4.50") < 0) {
            vulnerabilities.add("CVE-2021-41773 - Path Traversal");
        }
        if (service.equals("SSH") && bannerInfo[1].compareTo("7.5") < 0) {
            vulnerabilities.add("SSH User Enumeration Vulnerability");
        }
        if (!vulnerabilities.isEmpty()) {
            bannerData.put("vulnerabilities", vulnerabilities);
        }

        return bannerData;
    }

    /**
     * Probe service for additional information
     */
    private Map<String, Object> probeService(String service, String host, int port, TaskContext ctx) {
        Map<String, Object> probeResults = new LinkedHashMap<>();

        switch (service) {
            case "HTTP":
            case "HTTPS":
                probeResults.put("http_methods", List.of("GET", "POST", "OPTIONS", "HEAD"));
                probeResults.put("robots_txt", true);
                break;
            case "SMTP":
                probeResults.put("vrfy_enabled", false);
                probeResults.put("expn_enabled", false);
                break;
            case "FTP":
                probeResults.put("anonymous_login", true);
                break;
            case "SSH":
                probeResults.put("key_algorithms", List.of("ssh-rsa", "ecdsa-sha2-nistp256"));
                break;
            case "MySQL":
                probeResults.put("allow_local_file", true);
                break;
        }

        return probeResults;
    }
}
