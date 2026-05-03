package com.jabber.jabber.modules.reconnaissance.pingsweep;

import com.jabber.jabber.data.model.TaskContext;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * ProcessExecutor — Secure process orchestration with Sudo support.
 */
public class ProcessExecutor {

    public CommandRecord execute(String toolId, List<String> command, TaskContext ctx, long timeoutMs, String sudoPassword) {
        long startTime = System.currentTimeMillis();
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        int exitCode = -1;

        try {
            List<String> finalCommand = new ArrayList<>();
            if (sudoPassword != null && !sudoPassword.isBlank()) {
                finalCommand.addAll(List.of("sudo", "-S"));
                finalCommand.addAll(command);
            } else {
                finalCommand.addAll(command);
            }

            ProcessBuilder pb = new ProcessBuilder(finalCommand);
            Process p = pb.start();

            // If sudo is used, provide password via stdin
            if (sudoPassword != null && !sudoPassword.isBlank()) {
                try (PrintWriter out = new PrintWriter(new OutputStreamWriter(p.getOutputStream()))) {
                    out.println(sudoPassword);
                    out.flush();
                }
            }

            Thread outThread = new Thread(() -> captureStream(p.getInputStream(), stdout));
            Thread errThread = new Thread(() -> captureStream(p.getErrorStream(), stderr));
            outThread.start();
            errThread.start();

            boolean finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                ctx.log("[!] Timeout: " + toolId + " exceeded " + timeoutMs + "ms");
            } else {
                exitCode = p.exitValue();
            }

            outThread.join(500);
            errThread.join(500);

        } catch (Exception e) {
            stderr.append("Execution error: ").append(e.getMessage());
            ctx.log("[!] Error executing " + toolId + ": " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        return new CommandRecord(toolId, command, exitCode, stdout.toString(), stderr.toString(), duration);
    }

    private void captureStream(InputStream is, StringBuilder sb) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException ignored) {}
    }
}
