package com.jabber.jrts.modules.payload;

import java.util.Random;
import java.util.UUID;

/**
 * PayloadPolymorphicMutationModule - Generates polymorphic variants of payloads
 * Each variant has a unique structure but maintains the same functionality
 */
public class PayloadPolymorphicMutationModule {
    private final Random random = new Random();
    private final int mutationCount;

    public PayloadPolymorphicMutationModule(int mutationCount) {
        this.mutationCount = Math.max(1, mutationCount);
    }

    /**
     * Generate polymorphic variants of a payload
     */
    public String[] generatePolymorphicVariants(String payload) {
        String[] variants = new String[mutationCount];
        for (int i = 0; i < mutationCount; i++) {
            variants[i] = mutatePayload(payload, i);
        }
        return variants;
    }

    /**
     * Apply mutation to payload
     */
    private String mutatePayload(String payload, int variantId) {
        StringBuilder mutated = new StringBuilder();
        mutated.append("// VARIANT_").append(variantId).append("_").append(UUID.randomUUID()).append("\n");
        mutated.append(applyRandomTransformations(payload));
        return mutated.toString();
    }

    /**
     * Apply random code transformations
     */
    private String applyRandomTransformations(String payload) {
        String transformed = payload;
        
        if (shouldApply()) {
            transformed = injectNopInstructions(transformed);
        }
        if (shouldApply()) {
            transformed = reorderStatements(transformed);
        }
        if (shouldApply()) {
            transformed = insertDeadCode(transformed);
        }
        if (shouldApply()) {
            transformed = obfuscateVariables(transformed);
        }
        
        return transformed;
    }

    private boolean shouldApply() {
        return random.nextBoolean();
    }

    private String injectNopInstructions(String code) {
        return code + "\n// NOP_INJECT_" + System.currentTimeMillis();
    }

    private String reorderStatements(String code) {
        return code.replaceAll("(\\w+);", "{$1;}");
    }

    private String insertDeadCode(String code) {
        int deadCodeType = random.nextInt(3);
        switch (deadCodeType) {
            case 0: return code + "\nif(false){System.out.println(\"dead\");}";
            case 1: return code + "\nint _c="+(random.nextInt(100))+";";
            case 2: return code + "\nString _s=\"\"+System.currentTimeMillis();";
            default: return code;
        }
    }

    private String obfuscateVariables(String code) {
        return code.replaceAll("\\b(var|int|String)\\s+(\\w+)\\b", 
            "$1 _"+(random.nextInt(10000)));
    }

    /**
     * Check if two variants are semantically equivalent
     */
    public boolean areVariantsEquivalent(String variant1, String variant2) {
        return variant1.hashCode() != variant2.hashCode() && 
               extractPayloadCore(variant1).equals(extractPayloadCore(variant2));
    }

    private String extractPayloadCore(String variant) {
        return variant.replaceAll("//.*", "").replaceAll("\\s+", "");
    }

    /**
     * Get mutation statistics
     */
    public String getMutationStats() {
        return "PolymorphicMutationModule: " + mutationCount + " variants generated";
    }
}
