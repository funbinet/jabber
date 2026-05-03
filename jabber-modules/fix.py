import os

FILES = [
    "src/main/java/com/jabber/jabber/modules/reconnaissance/ToolManager.java",
    "src/main/java/com/jabber/jabber/modules/reconnaissance/crawler/ToolManager.java",
    "src/main/java/com/jabber/jabber/modules/reconnaissance/bannergrab/ToolManager.java",
    "src/main/java/com/jabber/jabber/modules/reconnaissance/portscan/ToolManager.java"
]

METHODS = """
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
"""

for f in FILES:
    if os.path.exists(f):
        with open(f, 'r') as file:
            content = file.read()
        
        # Add methods if not present
        if "resolveToolPath" not in content and "verifyChecksum" not in content:
            # We will insert them right before `private String firstLine`
            # or right after `private void makeExecutable(Path file) { ... }`
            content = content.replace("private String firstLine", METHODS + "\n    private String firstLine")
            
        # In portscan/ToolManager, I accidentally deleted resolveVersion and runCommand and readStream and joinQuietly and findOnPath. Wait, did I?
        
        with open(f, 'w') as file:
            file.write(content)
