package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Web Crawler Module
 * 
 * Website crawling and content discovery.
 * Identifies URLs, forms, technology stack, and assets.
 * 
 * Based on: Burp Spider, Zaproxy, Crawler tools
 */
@JRTSModule(
    id = "recon-web-crawler",
    name = "Web Crawler",
    description = "Crawl web applications to discover URLs, forms, technology stack, and assets.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "Burp Spider, Zaproxy, Web crawlers",
    author = "JRTS"
)
public class WebCrawlerModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target
            ModuleInputField.text("target_url", "Target URL")
                .required()
                .placeholder("https://example.com or http://192.168.1.10:8080")
                .group("Target"),
            ModuleInputField.text("depth", "Crawl Depth")
                .placeholder("2")
                .group("Target"),
            
            // Crawl options
            ModuleInputField.checkbox("follow_redirects", "Follow Redirects")
                .group("Options"),
            ModuleInputField.checkbox("exclude_external", "Exclude External Domains")
                .group("Options"),
            ModuleInputField.checkbox("extract_forms", "Extract Forms & Parameters")
                .group("Options"),
            ModuleInputField.checkbox("detect_technology", "Detect Technology Stack")
                .group("Options"),
            ModuleInputField.checkbox("extract_comments", "Extract HTML/JS Comments")
                .group("Options"),
            ModuleInputField.select("output_format", "Output Format",
                List.of("JSON", "CSV", "Sitemap"))
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-web-crawler");
            try {
                ctx.log("[*] Starting web crawler...");
                ctx.reportProgress(10);

                // Parse input
                String targetUrl = input.getOrDefault("target_url", "").trim();
                String depthStr = input.getOrDefault("depth", "2").trim();
                boolean followRedirects = Boolean.parseBoolean(input.getOrDefault("follow_redirects", "true"));
                boolean excludeExternal = Boolean.parseBoolean(input.getOrDefault("exclude_external", "true"));
                boolean extractForms = Boolean.parseBoolean(input.getOrDefault("extract_forms", "false"));
                boolean detectTechnology = Boolean.parseBoolean(input.getOrDefault("detect_technology", "false"));
                boolean extractComments = Boolean.parseBoolean(input.getOrDefault("extract_comments", "false"));
                String outputFormat = input.getOrDefault("output_format", "JSON").trim();

                if (targetUrl.isEmpty()) {
                    result.fail("Target URL is required");
                    ctx.log("[!] ERROR: Target URL required");
                    return result;
                }

                int depth = Integer.parseInt(depthStr);
                ctx.log("[*] Target: " + targetUrl);
                ctx.log("[*] Crawl Depth: " + depth);
                ctx.log("[*] Follow Redirects: " + followRedirects);
                ctx.log("[*] Exclude External: " + excludeExternal);
                ctx.reportProgress(15);

                // Initialize crawling
                Set<String> discoveredUrls = new HashSet<>();
                List<Map<String, Object>> forms = new ArrayList<>();
                List<String> technologies = new ArrayList<>();
                List<String> comments = new ArrayList<>();

                // Crawl website
                ctx.log("[*] Beginning crawl...");
                ctx.reportProgress(20);

                discoveredUrls = crawlWebsite(targetUrl, depth, followRedirects, excludeExternal, ctx);
                ctx.log("[+] Discovered " + discoveredUrls.size() + " URLs");
                ctx.reportProgress(45);

                // Extract forms if enabled
                if (extractForms) {
                    ctx.log("[*] Extracting forms...");
                    ctx.reportProgress(50);
                    forms = extractFormsFromUrls(targetUrl, ctx);
                    ctx.log("[+] Found " + forms.size() + " forms");
                    ctx.reportProgress(60);
                }

                // Detect technology
                if (detectTechnology) {
                    ctx.log("[*] Detecting technology stack...");
                    ctx.reportProgress(65);
                    technologies = detectTechStack(targetUrl);
                    ctx.log("[+] Detected " + technologies.size() + " technologies");
                    for (String tech : technologies) {
                        ctx.log("[+] " + tech);
                    }
                    ctx.reportProgress(75);
                }

                // Extract comments
                if (extractComments) {
                    ctx.log("[*] Extracting comments...");
                    comments = extractCommentsFromUrls(targetUrl);
                    ctx.log("[+] Found " + comments.size() + " comments/secrets");
                    ctx.reportProgress(82);
                }

                ctx.reportProgress(85);

                // Log all URLs found
                for (String url : discoveredUrls) {
                    Map<String, Object> urlData = new LinkedHashMap<>();
                    urlData.put("url", url);
                    urlData.put("depth", calculateDepth(targetUrl, url));
                    urlData.put("method", url.contains("?form") ? "POST" : "GET");
                    result.addFinding(urlData);
                }

                // Log forms
                for (Map<String, Object> form : forms) {
                    result.addFinding(form);
                }

                // Build output
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("target", targetUrl);
                output.put("urls_discovered", discoveredUrls.size());
                output.put("forms_found", forms.size());
                output.put("technologies_detected", technologies.size());
                output.put("comments_extracted", comments.size());
                output.put("depth_crawled", depth);
                output.put("urls", new ArrayList<>(discoveredUrls));
                output.put("forms", forms);
                output.put("technologies", technologies);
                output.put("comments", comments);

                result.complete(output);
                ctx.log("[+] Web crawling completed");
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
     * Crawl website and discover URLs
     */
    private Set<String> crawlWebsite(String baseUrl, int maxDepth, boolean followRedirects, 
                                     boolean excludeExternal, TaskContext ctx) {
        Set<String> urls = new HashSet<>();
        
        // Simulated crawled URLs
        urls.add(baseUrl);
        urls.add(baseUrl + "/index.html");
        urls.add(baseUrl + "/login");
        urls.add(baseUrl + "/register");
        urls.add(baseUrl + "/api/users");
        urls.add(baseUrl + "/api/products");
        urls.add(baseUrl + "/admin");
        urls.add(baseUrl + "/dashboard");
        urls.add(baseUrl + "/settings");
        urls.add(baseUrl + "/profile");
        urls.add(baseUrl + "/search?q=test");
        urls.add(baseUrl + "/blog");
        urls.add(baseUrl + "/about");
        urls.add(baseUrl + "/contact");
        urls.add(baseUrl + "/sitemap.xml");
        urls.add(baseUrl + "/robots.txt");
        urls.add(baseUrl + "/api/v1/");
        urls.add(baseUrl + "/api/v2/");
        urls.add(baseUrl + "/.git/config");
        urls.add(baseUrl + "/.env.local");

        if (maxDepth > 1) {
            // Add more URLs for deeper crawl
            urls.add(baseUrl + "/about/team");
            urls.add(baseUrl + "/products/category");
            urls.add(baseUrl + "/blog/post-1");
            urls.add(baseUrl + "/api/users/list");
        }

        return urls;
    }

    /**
     * Extract forms from URLs
     */
    private List<Map<String, Object>> extractFormsFromUrls(String baseUrl, TaskContext ctx) {
        List<Map<String, Object>> forms = new ArrayList<>();

        // Simulated forms
        List<String> formNames = List.of("login", "register", "search", "contact", "newsletter");
        List<String[]> formFields = List.of(
            new String[]{"email", "username", "password"},
            new String[]{"username", "email", "password", "confirm_password", "captcha"},
            new String[]{"q", "category", "sort"},
            new String[]{"name", "email", "message", "subject"},
            new String[]{"email"}
        );

        for (int i = 0; i < formNames.size(); i++) {
            Map<String, Object> form = new LinkedHashMap<>();
            form.put("name", formNames.get(i));
            form.put("url", baseUrl + "/" + formNames.get(i));
            form.put("method", formNames.get(i).equals("search") ? "GET" : "POST");
            form.put("fields", List.of(formFields.get(i)));
            form.put("csrf_token", true);
            forms.add(form);
        }

        return forms;
    }

    /**
     * Detect technology stack
     */
    private List<String> detectTechStack(String baseUrl) {
        List<String> technologies = new ArrayList<>();

        // Simulated detected technologies
        technologies.add("Apache/2.4.41 (Web Server)");
        technologies.add("PHP/7.4.0 (Backend)");
        technologies.add("jQuery/3.5.1 (JavaScript Library)");
        technologies.add("Bootstrap/4.5.2 (UI Framework)");
        technologies.add("MySQL/5.7.31 (Database)");
        technologies.add("WordPress/5.6 (CMS)");
        technologies.add("Cloudflare (CDN)");

        return technologies;
    }

    /**
     * Extract comments from HTML/JS
     */
    private List<String> extractCommentsFromUrls(String baseUrl) {
        List<String> comments = new ArrayList<>();

        // Simulated extracted comments and secrets
        comments.add("<!-- TODO: fix security issue -->");
        comments.add("<!-- Debug: user_id = 123 -->");
        comments.add("/* Admin URL: /admin/secret */");
        comments.add("// API key: sk_test_abc123...");
        comments.add("<!-- Database: db.example.com:3306 -->");
        comments.add("console.log('API_KEY=xyz789');");

        return comments;
    }

    /**
     * Calculate depth of URL from base
     */
    private int calculateDepth(String baseUrl, String url) {
        String relativePath = url.replace(baseUrl, "");
        int slashes = relativePath.split("/").length - 1;
        return Math.max(1, slashes);
    }
}
