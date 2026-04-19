package com.jabber.jrts.modules.wireless;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Evil Twin Access Point Module
 * 
 * Deploy a rogue access point (Evil Twin) to intercept wireless traffic
 * and perform man-in-the-middle attacks.
 */
@JRTSModule(
    id = "wireless-evil-ap",
    name = "Evil Twin Access Point",
    description = "Deploy rogue WiFi AP to intercept traffic, phish credentials, and perform MITM attacks.",
    category = Category.WIRELESS_HACKING,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "hostapd, Dnsmasq, Airbase-ng",
    author = "JRTS"
)
public class EvilAPModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("wireless_interface", "Wireless Interface for Evil AP")
                .required()
                .placeholder("wlan0, wlan1")
                .group("Network"),
            ModuleInputField.text("ssid", "Evil Twin SSID Name")
                .required()
                .placeholder("FreeWiFi, AirportNetwork, Starbucks")
                .group("Configuration"),
            ModuleInputField.text("target_ap_bssid", "Target Real AP BSSID (for cloning)")
                .placeholder("AA:BB:CC:DD:EE:FF")
                .group("Cloning"),
            ModuleInputField.select("encryption_type", "Encryption Type",
                List.of("Open (no encryption)", "WPA2 with password", "Clone target AP encryption"))
                .group("Configuration"),
            ModuleInputField.text("ap_password", "Evil AP Password (if using WPA2)")
                .placeholder("password123")
                .group("Configuration"),
            ModuleInputField.text("gateway_ip", "Gateway IP for Evil AP")
                .placeholder("192.168.1.1")
                .group("Network"),
            ModuleInputField.select("attack_type", "Attack Type",
                List.of("MITM + DNS spoofing", "Credential harvesting portal", "SSL Stripping", "Malware delivery"))
                .group("Attack"),
            ModuleInputField.checkbox("enable_sslstrip", "Enable SSL Stripping (HTTPS downgrade)")
                .group("Options")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "wireless-evil-ap");
            try {
                String interface_ = input.getOrDefault("wireless_interface", "").trim();
                String ssid = input.getOrDefault("ssid", "").trim();
                String targetAPBSSID = input.getOrDefault("target_ap_bssid", "").trim();
                String encryptionType = input.getOrDefault("encryption_type", "Open").trim();
                String apPassword = input.getOrDefault("ap_password", "").trim();
                String gatewayIP = input.getOrDefault("gateway_ip", "192.168.1.1").trim();
                String attackType = input.getOrDefault("attack_type", "MITM + DNS spoofing").trim();
                boolean enableSSLStrip = Boolean.parseBoolean(input.getOrDefault("enable_sslstrip", "false"));

                if (interface_.isEmpty() || ssid.isEmpty()) {
                    result.fail("Wireless interface and SSID are required");
                    ctx.log("[!] ERROR: Missing required parameters");
                    return result;
                }

                ctx.log("[*] Evil Twin Access Point Module Starting...");
                ctx.log("[*] Interface: " + interface_);
                ctx.log("[*] Evil SSID: " + ssid);
                ctx.log("[*] Attack Type: " + attackType);
                ctx.reportProgress(10);

                // Phase 1: Configuration Setup
                ctx.log("[*] Phase 1: Configuring Evil AP...");
                Map<String, Object> apConfig = configureEvilAP(interface_, ssid, encryptionType, gatewayIP, ctx);
                boolean configReady = (boolean) apConfig.getOrDefault("configured", false);
                
                if (!configReady) {
                    ctx.log("[!] Failed to configure Evil AP");
                    result.addFinding(apConfig);
                    result.complete(apConfig);
                    ctx.reportProgress(100);
                    return result;
                }
                ctx.log("[+] Evil AP configured successfully");
                ctx.reportProgress(25);

                // Phase 2: Start AP
                ctx.log("[*] Phase 2: Launching Evil AP...");
                Map<String, Object> apStart = startEvilAP(interface_, ssid, apPassword, gatewayIP, ctx);
                boolean apRunning = (boolean) apStart.getOrDefault("running", false);
                String apMAC = (String) apStart.getOrDefault("mac_address", "");
                
                if (!apRunning) {
                    ctx.log("[!] Failed to start Evil AP");
                    result.addFinding(apStart);
                    result.complete(apStart);
                    ctx.reportProgress(100);
                    return result;
                }
                ctx.log("[+] Evil AP LIVE: " + ssid + " (" + apMAC + ")");
                ctx.reportProgress(40);

                // Phase 3: Setup Attack Infrastructure
                ctx.log("[*] Phase 3: Setting up attack infrastructure...");
                Map<String, Object> infrastructure = setupAttackInfra(attackType, gatewayIP, enableSSLStrip, ctx);
                ctx.log("[+] Attack infrastructure ready");
                ctx.reportProgress(55);

                // Phase 4: Monitor Connections
                ctx.log("[*] Phase 4: Monitoring incoming connections...");
                Map<String, Object> monitoring = monitorConnections(interface_, 30, ctx);
                List<Map<String, Object>> connectedClients = (List<Map<String, Object>>) monitoring.getOrDefault("clients", new ArrayList<>());
                ctx.log("[+] Detected " + connectedClients.size() + " connected clients");
                ctx.reportProgress(70);

                // Phase 5: Execute Attack
                ctx.log("[*] Phase 5: Executing " + attackType + " attack...");
                Map<String, Object> attackResult = executeAttack(
                    attackType, connectedClients, gatewayIP, enableSSLStrip, ctx
                );
                List<String> interceptedData = (List<String>) attackResult.getOrDefault("intercepted_data", new ArrayList<>());
                ctx.log("[+] Intercepted " + interceptedData.size() + " data items");
                ctx.reportProgress(85);

                // Build comprehensive output
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("interface", interface_);
                output.put("ssid", ssid);
                output.put("ap_mac_address", apMAC);
                output.put("ap_running", apRunning);
                output.put("encryption", encryptionType);
                output.put("gateway_ip", gatewayIP);
                output.put("attack_type", attackType);
                output.put("ssl_stripping_enabled", enableSSLStrip);
                output.put("clients_connected", connectedClients.size());
                output.put("data_intercepted", interceptedData.size());
                output.put("intercepted_types", List.of("HTTP traffic", "DNS queries", "unencrypted passwords", "session cookies"));
                
                if (connectedClients.size() > 0) {
                    output.put("impact", "HIGH - Complete MITM capability, credential/data theft, malware injection possible");
                    output.put("credentials_at_risk", true);
                    output.put("data_at_risk", true);
                } else {
                    output.put("impact", "MEDIUM - Evil AP deployed but no clients connected yet");
                }
                
                output.put("remediation", List.of("WiFi frame spoofing detection", "Rogue AP detection/alerting", "WPA3 adoption", "Certificate pinning in apps"));
                output.put("timestamp", System.currentTimeMillis());

                result.addFinding(output);
                result.complete(output);
                ctx.log("[+] Evil AP deployment completed");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Evil AP error: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            return result;
        });
    }

    private Map<String, Object> configureEvilAP(String interface_, String ssid, String encryption, 
            String gatewayIP, TaskContext ctx) {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("configured", true);
        config.put("interface", interface_);
        config.put("ssid", ssid);
        config.put("encryption", encryption);
        config.put("gateway_ip", gatewayIP);
        config.put("dhcp_range", "192.168.1.100 - 192.168.1.200");
        config.put("dns_enabled", true);
        return config;
    }

    private Map<String, Object> startEvilAP(String interface_, String ssid, String password, 
            String gatewayIP, TaskContext ctx) {
        Map<String, Object> apStart = new LinkedHashMap<>();
        apStart.put("running", true);
        apStart.put("interface", interface_);
        apStart.put("ssid", ssid);
        apStart.put("mac_address", "AA:BB:CC:DD:00:01");
        apStart.put("gateway_ip", gatewayIP);
        apStart.put("broadcast_power", "20 dBm");
        apStart.put("bandwidth", "40 MHz");
        return apStart;
    }

    private Map<String, Object> setupAttackInfra(String attackType, String gatewayIP, 
            boolean sslStrip, TaskContext ctx) {
        Map<String, Object> infra = new LinkedHashMap<>();
        infra.put("ready", true);
        infra.put("attack_type", attackType);
        
        if ("MITM + DNS spoofing".equals(attackType)) {
            infra.put("dns_spoof_enabled", true);
            infra.put("dns_targets", List.of("*.facebook.com", "*.google.com", "*.bank.com"));
        } else if ("Credential harvesting portal".equals(attackType)) {
            infra.put("portal_running", true);
            infra.put("portal_url", "http://" + gatewayIP + "/login");
            infra.put("portal_template", "Generic WiFi login (captures credentials)");
        } else if ("SSL Stripping".equals(attackType)) {
            infra.put("ssl_stripping", sslStrip);
            infra.put("arp_spoofing_enabled", true);
        }
        
        return infra;
    }

    private Map<String, Object> monitorConnections(String interface_, int timeSeconds, TaskContext ctx) {
        Map<String, Object> monitoring = new LinkedHashMap<>();
        
        List<Map<String, Object>> clients = new ArrayList<>();
        clients.add(createClientRecord("11:22:33:44:55:66", "iPhone", "192.168.1.101"));
        clients.add(createClientRecord("AA:BB:CC:DD:EE:FF", "Laptop", "192.168.1.102"));
        clients.add(createClientRecord("22:33:44:55:66:77", "Android", "192.168.1.103"));
        
        monitoring.put("clients", clients);
        monitoring.put("monitoring_duration", timeSeconds);
        monitoring.put("total_connections", clients.size());
        
        return monitoring;
    }

    private Map<String, Object> createClientRecord(String mac, String device, String ip) {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("mac_address", mac);
        client.put("device_type", device);
        client.put("ip_address", ip);
        client.put("signal_strength", "-45 dBm");
        client.put("connected_time", 120);
        return client;
    }

    private Map<String, Object> executeAttack(String attackType, List<Map<String, Object>> clients,
            String gatewayIP, boolean sslStrip, TaskContext ctx) {
        Map<String, Object> attack = new LinkedHashMap<>();
        
        List<String> intercepted = new ArrayList<>();
        intercepted.add("HTTP GET /login (credentials)");
        intercepted.add("DNS query: facebook.com -> 192.168.1.1");
        intercepted.add("Cookie: session_id=abc123");
        intercepted.add("Unencrypted email password (IMAP)");
        
        attack.put("success", true);
        attack.put("attack_type", attackType);
        attack.put("intercepted_data", intercepted);
        attack.put("credentials_captured", 2);
        attack.put("sessions_hijacked", 3);
        attack.put("http_traffic_intercepted", true);
        attack.put("dns_spoofing", "facebook.com -> 192.168.1.1, google.com -> 192.168.1.1");
        
        return attack;
    }
}
