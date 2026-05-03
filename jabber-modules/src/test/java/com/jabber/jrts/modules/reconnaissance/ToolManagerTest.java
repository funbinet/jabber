package com.jabber.jabber.modules.reconnaissance;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ToolManagerTest {

    private Path tempDir;

    @AfterEach
    void cleanup() throws Exception {
        if (tempDir != null) {
            try (var stream = Files.walk(tempDir)) {
                stream.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) {}
                });
            }
        }
    }

    @Test
    void detectsToolInModuleDirectory() throws Exception {
        tempDir = Files.createTempDirectory("jabber_tool_test_");
        ToolManager.ToolDefinition def = ToolManager.ToolDefinition.github(
            "dummy", "Dummy", "Test tool", "owner", "repo", "dummy", List.of(), ""
        );

        String binaryName = def.binaryFileName();
        Path binaryPath = tempDir.resolve(binaryName);
        Files.writeString(binaryPath, "#!/bin/sh\necho test\n");
        binaryPath.toFile().setExecutable(true);

        ToolManager manager = ToolManager.createForTesting(tempDir, List.of(def));
        ToolManager.ToolStatus status = manager.getToolStatus("dummy");

        assertTrue(status.isInstalled());
        assertTrue(status.getPath().endsWith(binaryName));
    }
}
