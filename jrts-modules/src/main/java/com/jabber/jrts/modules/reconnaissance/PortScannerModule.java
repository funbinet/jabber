package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

@JRTSModule(
    id = "recon-portscanner",
    name = "Port Scanner",
    description = "High-performance, pure-Java CIDR-aware port scanner with TCP/UDP capabilities and service enumeration.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "Pure Java NIO/Sockets + Virtual Threads",
    author = "JRTS"
)
public class PortScannerModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Scan Mode", List.of("discovery_sweep", "deep_port_scan", "service_enumeration", "udp_ping"))
                .required()
                .group("Core"),
            ModuleInputField.text("target_ips", "Target IP(s) or CIDR")
                .required()
                .placeholder("192.168.1.10 or 10.0.0.0/24")
                .group("Core"),
            ModuleInputField.text("port_range", "Port Range")
                .placeholder("1-1024, 3389, 8080 (Leave empty for mode default)")
                .group("Scan Config"),
            ModuleInputField.text("timeout_ms", "Timeout (ms)")
                .placeholder("2000")
                .group("Scan Config"),
            ModuleInputField.text("concurrency", "Max Concurrent Connections")
                .placeholder("500")
                .group("Performance")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-portscanner");
            try {
                String mode = input.getOrDefault("mode", "discovery_sweep");
                String targetRaw = input.getOrDefault("target_ips", "").trim();
                String portsRaw = input.getOrDefault("port_range", "").trim();
                
                if (targetRaw.isEmpty()) {
                    result.fail("Target IP(s) or CIDR is required.");
                    ctx.log("[!] ERROR: Target is missing.");
                    return result;
                }

                int timeoutMs = 2000;
                try { timeoutMs = Integer.parseInt(input.getOrDefault("timeout_ms", "2000").trim()); } catch (Exception ignored){}
                final int finalTimeoutMs = timeoutMs;
                
                int concurrency = 500;
                try { concurrency = Integer.parseInt(input.getOrDefault("concurrency", "500").trim()); } catch (Exception ignored){}
                final int finalConcurrency = concurrency;

                ctx.log("[*] Mode: " + mode);
                ctx.log("[*] Expanding targets: " + targetRaw);
                List<String> targetIps = expandIps(targetRaw);
                ctx.log("[+] Expanded to " + targetIps.size() + " IPs.");
                
                if (targetIps.size() > 65535) {
                    result.fail("Target scope too large (Max 65535 IPs allowed per scan for safety).");
                    ctx.log("[!] Refusing excessive subnet scope.");
                    return result;
                }

                List<Integer> ports = parsePorts(portsRaw, mode);
                ctx.log("[*] Ports to scan per IP: " + ports.size());
                long totalChecks = (long)targetIps.size() * ports.size();
                ctx.log("[*] Total connection attempts: " + totalChecks);
                
                ctx.reportProgress(5);

                ExecutorService executor;
                try {
                    executor = Executors.newVirtualThreadPerTaskExecutor();
                } catch (NoSuchMethodError e) {
                    executor = Executors.newFixedThreadPool(Math.min(100, finalConcurrency));
                }

                Semaphore connectionLimits = new Semaphore(finalConcurrency);
                List<CompletableFuture<ScanResult>> futures = new ArrayList<>();

                int totalTasks = targetIps.size() * ports.size();
                int submitted = 0;

                for (String ip : targetIps) {
                    for (int port : ports) {
                        futures.add(CompletableFuture.supplyAsync(() -> {
                            try {
                                connectionLimits.acquire();
                                return scanPort(ip, port, mode, finalTimeoutMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return new ScanResult(ip, port, "ERROR", null);
                            } finally {
                                connectionLimits.release();
                            }
                        }, executor));
                        
                        submitted++;
                        if (submitted % 5000 == 0) {
                            ctx.log("[~] Queued " + submitted + "/" + totalChecks + " tasks...");
                        }
                    }
                }

                ctx.log("[*] All tasks queued. Awaiting completion...");
                
                List<Map<String, Object>> openPorts = new ArrayList<>();
                int completed = 0;
                
                for (CompletableFuture<ScanResult> future : futures) {
                    ScanResult res = future.get();
                    if (res != null && (res.state.equals("OPEN") || res.state.equals("OPEN|FILTERED"))) {
                        Map<String, Object> map = new LinkedHashMap<>();
                        map.put("ip", res.ip);
                        map.put("port", res.port);
                        map.put("state", res.state);
                        map.put("service", res.service);
                        if (res.banner != null) {
                            map.put("banner", res.banner);
                        }
                        openPorts.add(map);
                        result.addFinding(map);
                        
                        if (res.banner != null) {
                            ctx.log(String.format("[+] %s:%d %s (%s) - %s", res.ip, res.port, res.state, res.service, res.banner.replace("\r", "").replace("\n", " ")));
                        } else {
                            ctx.log(String.format("[+] %s:%d %s (%s)", res.ip, res.port, res.state, res.service));
                        }
                    }
                    completed++;
                    if (completed % 1000 == 0 || completed == totalTasks) {
                        int p = 5 + (int)(((double)completed / totalTasks) * 90);
                        ctx.reportProgress(p);
                    }
                }

                ctx.log("[+] Scan completed. Enumerable exposed services: " + openPorts.size());

                Map<String, Object> output = new LinkedHashMap<>();
                output.put("target_expr", targetRaw);
                output.put("mode", mode);
                output.put("ips_scanned", targetIps.size());
                output.put("ports_per_ip", ports.size());
                output.put("total_open", openPorts.size());
                output.put("results", openPorts);
                
                result.complete(output);
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Execution Error: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            return result;
        });
    }

    private static class ScanResult {
        String ip; int port; String state; String service; String banner;
        public ScanResult(String ip, int port, String state, String service) {
            this.ip = ip; this.port = port; this.state = state; this.service = service;
        }
    }

    private ScanResult scanPort(String ip, int port, String mode, int timeoutMs) {
        if ("udp_ping".equals(mode)) {
            return scanUdp(ip, port, timeoutMs);
        } else {
            return scanTcp(ip, port, mode, timeoutMs);
        }
    }

    private ScanResult scanTcp(String ip, int port, String mode, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            ScanResult res = new ScanResult(ip, port, "OPEN", guessService(port));
            
            if ("service_enumeration".equals(mode)) {
                res.banner = grabBanner(socket, port);
            }
            return res;
        } catch (Exception e) {
            return new ScanResult(ip, port, "CLOSED/FILTERED", null);
        }
    }

    private String grabBanner(Socket socket, int port) {
        try {
            OutputStream os = socket.getOutputStream();
            InputStream is = socket.getInputStream();
            
            if (port == 80 || port == 443 || port == 8080 || port == 8443) {
                os.write("HEAD / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                os.flush();
            } else if (port != 22 && port != 21) {
                os.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                os.flush();
            }
            
            byte[] buf = new byte[1024];
            int read = is.read(buf);
            if (read > 0) {
                String banner = new String(buf, 0, read, StandardCharsets.UTF_8).trim();
                return banner.isEmpty() ? null : (banner.length() > 200 ? banner.substring(0, 200) + "..." : banner);
            }
        } catch (Exception e) {
            // Ignored timeout or io abort
        }
        return null;
    }

    private ScanResult scanUdp(String ip, int port, int timeoutMs) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            
            byte[] payload = getUdpProbe(port);
            InetAddress address = InetAddress.getByName(ip);
            DatagramPacket packet = new DatagramPacket(payload, payload.length, address, port);
            socket.send(packet);
            
            byte[] receiveBuf = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuf, receiveBuf.length);
            socket.receive(receivePacket);
            
            return new ScanResult(ip, port, "OPEN", guessService(port));
        } catch (SocketTimeoutException | PortUnreachableException e) {
             if (e instanceof PortUnreachableException) {
                 return new ScanResult(ip, port, "CLOSED", guessService(port));
             }
             return new ScanResult(ip, port, "OPEN|FILTERED", guessService(port));
        } catch (Exception e) {
             return new ScanResult(ip, port, "ERROR", null);
        }
    }

    private byte[] getUdpProbe(int port) {
        if (port == 53) {
            // DNS standard query for example.com
            return new byte[]{
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
            };
        } else if (port == 161) {
            // SNMPv1 GetRequest public
            return new byte[]{
                0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 
                (byte)0xa0, 0x19, 0x02, 0x04, 0x11, 0x22, 0x33, 0x44, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 
                0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00
            };
        } else if (port == 123) {
            // NTP Request
            byte[] ntp = new byte[48];
            ntp[0] = 0x1b; 
            return ntp;
        }
        return new byte[]{0x00};
    }

    private List<String> expandIps(String input) {
        List<String> list = new ArrayList<>();
        input = input.trim();
        if (input.contains(",")) {
            for(String s : input.split(",")) {
                 list.addAll(expandIps(s.trim()));
            }
            return list;
        }
        if (input.contains("/")) {
            try {
                String[] parts = input.split("/");
                String ip = parts[0];
                int prefix = Integer.parseInt(parts[1]);
                
                if (prefix < 16) {
                     prefix = 16; // Prevent extreme arrays > 65k
                }
                
                InetAddress addr = InetAddress.getByName(ip);
                byte[] bytes = addr.getAddress();
                int ipInt = ByteBuffer.wrap(bytes).getInt();
                int maskInt = ~((1 << (32 - prefix)) - 1);
                
                int netInt = ipInt & maskInt;
                int broadcastInt = netInt | ~maskInt;
                
                for (int i = netInt + 1; i < broadcastInt; i++) {
                    byte[] ipBytes = ByteBuffer.allocate(4).putInt(i).array();
                    list.add(InetAddress.getByAddress(ipBytes).getHostAddress());
                }
                return list;
            } catch (Exception e) {
                list.add(input);
            }
        } else if (input.contains("-")) {
             try {
                  String[] split = input.split("-");
                  String base = split[0].substring(0, split[0].lastIndexOf('.') + 1);
                  int start = Integer.parseInt(split[0].substring(split[0].lastIndexOf('.') + 1));
                  int end = Integer.parseInt(split[1].trim());
                  for(int i = start; i <= end && i <= 255; i++) {
                       list.add(base + i);
                  }
             } catch(Exception e) {
                  list.add(input);
             }
        } else {
            list.add(input);
        }
        return list;
    }

    private List<Integer> parsePorts(String input, String mode) {
        if (input == null || input.trim().isEmpty()) {
            if ("discovery_sweep".equals(mode)) return Arrays.asList(21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5900, 8080);
            if ("deep_port_scan".equals(mode)) {
                List<Integer> all = new ArrayList<>(65535);
                for(int i=1; i<=65535; i++) all.add(i);
                return all;
            }
            if ("service_enumeration".equals(mode)) return Arrays.asList(21, 22, 25, 80, 443, 445, 3306, 3389, 8080);
            if ("udp_ping".equals(mode)) return Arrays.asList(53, 67, 123, 137, 138, 161, 500);
        }
        
        Set<Integer> ports = new LinkedHashSet<>();
        for (String part : input.split(",")) {
            part = part.trim();
            if (part.contains("-")) {
                try {
                     String[] s = part.split("-");
                     int start = Integer.parseInt(s[0].trim());
                     int end = Integer.parseInt(s[1].trim());
                     for(int i = start; i <= end && i <= 65535; i++) ports.add(i);
                } catch(Exception ignored){}
            } else {
                try {
                     int p = Integer.parseInt(part);
                     if (p > 0 && p <= 65535) ports.add(p);
                } catch (Exception ignored){}
            }
        }
        return new ArrayList<>(ports);
    }

    private String guessService(int p) {
        return switch(p) {
            case 21 -> "FTP"; case 22 -> "SSH"; case 23 -> "Telnet"; case 25 -> "SMTP";
            case 53 -> "DNS"; case 67 -> "DHCP"; case 80 -> "HTTP"; case 110 -> "POP3"; case 111 -> "RPC";
            case 123 -> "NTP"; case 135 -> "MSRPC"; case 137 -> "NetBIOS-NS"; case 139 -> "NetBIOS-SSN";
            case 143 -> "IMAP"; case 161 -> "SNMP"; case 443 -> "HTTPS"; case 445 -> "SMB"; case 500 -> "IKE";
            case 1433 -> "MSSQL"; case 1521 -> "Oracle"; case 3306 -> "MySQL"; case 3389 -> "RDP";
            case 5900 -> "VNC"; case 8080 -> "HTTP-Alt"; case 8443 -> "HTTPS-Alt"; default -> "Unknown";
        };
    }
}
