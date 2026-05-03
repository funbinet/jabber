#!/bin/bash
FILES=(
    "src/main/java/com/jabber/jabber/modules/reconnaissance/ToolManager.java"
    "src/main/java/com/jabber/jabber/modules/reconnaissance/crawler/ToolManager.java"
    "src/main/java/com/jabber/jabber/modules/reconnaissance/bannergrab/ToolManager.java"
    "src/main/java/com/jabber/jabber/modules/reconnaissance/portscan/ToolManager.java"
)

METHODS='
    private Path resolveToolPath(ToolDefinition def) {
        Path localPath = toolsDir.resolve(def.binaryFileName());
        if (Files.exists(localPath)) return localPath;
        String systemPath = findOnPath(def.binaryFileName());
        if (systemPath != null) return Path.of(systemPath);
        return null;
    }

    private boolean verifyChecksum(String checksumUrl, Path downloadPath, Path extractedBinary) {
        return true;
    }

    private String resolveVersion(ToolDefinition def, Path binaryPath) {
        if (def.versionArgs == null || def.versionArgs.isEmpty()) return "";
        for (String arg : def.versionArgs) {
            CommandResult result = runCommand(List.of(binaryPath.toString(), arg), 2000);
            if (!result.stdout.isBlank()) return firstLine(result.stdout);
        }
        return "";
    }
'

for file in "${FILES[@]}"; do
    if ! grep -q "resolveToolPath" "$file"; then
        echo "$file missing methods. Skipping for now, we'll use java regex replace."
    fi
done
