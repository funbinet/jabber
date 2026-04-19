package com.jabber.jrts.core.plugin;

import com.jabber.jrts.data.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Plugin Registry - discovers, loads, and manages JRTS modules.
 * Uses Spring classpath scanning to auto-discover all @JRTSModule annotated classes
 * from the authoritative source: com.jabber.jrts.modules.*
 *
 * NO manual registration. NO fallback generators. NO generated packages.
 * Every module is discovered from the verified module directory structure.
 */
@Component
public class PluginRegistry {

    private static final Logger log = LoggerFactory.getLogger(PluginRegistry.class);
    private static final String MODULE_BASE_PACKAGE = "com.jabber.jrts.modules";

    private final Map<String, JRTSModuleInterface> modules = new ConcurrentHashMap<>();
    private final Map<String, ModuleDescriptor> descriptors = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        log.info("=== JRTS Plugin Registry Initializing ===");
        log.info("Scanning package: {} for @JRTSModule annotations...", MODULE_BASE_PACKAGE);
        scanAndRegisterModules();
        log.info("=== Registry Complete: {} modules across {} categories ===",
            modules.size(), getCategories().size());

        // Log per-category breakdown
        for (Category cat : getCategories()) {
            long count = getByCategory(cat).size();
            log.info("  [{}] {} modules", cat.getDisplayName(), count);
        }
    }

    /**
     * Auto-discover and register all @JRTSModule annotated classes using Spring's
     * ClassPathScanningCandidateComponentProvider. This ensures 100% alignment
     * between the filesystem and the registry — no manual registration needed.
     */
    private void scanAndRegisterModules() {
        ClassPathScanningCandidateComponentProvider scanner =
            new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(JRTSModule.class));

        Set<BeanDefinition> candidates = scanner.findCandidateComponents(MODULE_BASE_PACKAGE);
        log.info("Found {} @JRTSModule annotated classes on classpath", candidates.size());

        int registered = 0;
        int failed = 0;

        for (BeanDefinition bd : candidates) {
            String className = bd.getBeanClassName();
            try {
                Class<?> clazz = Class.forName(className);

                // Verify it implements JRTSModuleInterface
                if (!JRTSModuleInterface.class.isAssignableFrom(clazz)) {
                    log.warn("  [!] {} has @JRTSModule but does not implement JRTSModuleInterface — skipping", className);
                    failed++;
                    continue;
                }

                @SuppressWarnings("unchecked")
                JRTSModuleInterface instance = (JRTSModuleInterface) clazz.getDeclaredConstructor().newInstance();
                registerModule(instance);
                registered++;

            } catch (Exception e) {
                log.warn("  [!] Failed to instantiate module: {} — {}", className, e.getMessage());
                failed++;
            }
        }

        log.info("Registration complete: {} succeeded, {} failed", registered, failed);
    }

    public void registerModule(JRTSModuleInterface module) {
        ModuleDescriptor desc = module.getDescriptor();
        if (desc != null) {
            modules.put(desc.getId(), module);
            descriptors.put(desc.getId(), desc);
            log.debug("  [+] Registered: {} ({}) [{}]",
                desc.getName(), desc.getCategory().getDisplayName(),
                desc.getRiskLevel().getLabel());
        }
    }

    public JRTSModuleInterface getModule(String id) {
        return modules.get(id);
    }

    public ModuleDescriptor getDescriptor(String id) {
        return descriptors.get(id);
    }

    public List<ModuleDescriptor> getAllDescriptors() {
        return new ArrayList<>(descriptors.values());
    }

    public List<ModuleDescriptor> getByCategory(Category category) {
        return descriptors.values().stream()
            .filter(d -> d.getCategory() == category)
            .sorted(Comparator.comparing(ModuleDescriptor::getName))
            .collect(Collectors.toList());
    }

    public Set<Category> getCategories() {
        return descriptors.values().stream()
            .map(ModuleDescriptor::getCategory)
            .collect(Collectors.toCollection(TreeSet::new));
    }

    public int getModuleCount() {
        return modules.size();
    }
}
