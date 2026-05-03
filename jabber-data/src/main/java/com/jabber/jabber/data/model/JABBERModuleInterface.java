package com.jabber.jabber.data.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Interface that all JABBER modules must implement.
 * Defines the standard lifecycle for module execution.
 */
public interface JABBERModuleInterface {

    /**
     * Returns the input schema describing required and optional inputs.
     */
    List<ModuleInputField> getInputSchema();

    /**
     * Execute the module with the given input parameters.
     *
     * @param input    Map of parameter name to value, as provided by the UI
     * @param context  Execution context for logging, progress, and artifact storage
     * @return CompletableFuture resolving to the module result
     */
    CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext context);

    /**
     * Cleanup resources after execution (called regardless of success/failure).
     */
    default void cleanup() {}

    /**
     * Returns the module descriptor, auto-built from @JABBERModule annotation.
     */
    default ModuleDescriptor getDescriptor() {
        JABBERModule ann = this.getClass().getAnnotation(JABBERModule.class);
        if (ann == null) return null;
        ModuleDescriptor d = new ModuleDescriptor(
            ann.id(), ann.name(), ann.description(),
            ann.category(), ann.riskLevel(), ann.version()
        );
        d.setAuthor(ann.author());
        d.setSourceRef(ann.sourceRef());
        d.setInputSchema(getInputSchema());
        return d;
    }
}
