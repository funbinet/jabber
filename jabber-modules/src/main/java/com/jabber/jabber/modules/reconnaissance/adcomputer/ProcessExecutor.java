package com.jabber.jabber.modules.reconnaissance.adcomputer;

import com.jabber.jabber.data.model.TaskContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * ProcessExecutor — Thread-safe command execution with automatic .log artifact persistence.
 * Leverages native ProcessBuilder for argument escaping to prevent shell injection.
 */
public class ProcessExecutor {

    private static final String LOGS_DIR = "reports/logs";

    public static CommandRecord execute(
            String toolId,
            String executablePath,
            List<String> arguments,
            long timeoutMs,
            TaskContext ctx,
            Consumer<String> stdOutProcessor,
            Consumer<String> stdErrProcessor) {

        CommandRecord record = new CommandRecord();
        record.tool = toolId;

        List<String> commandList = new ArrayList<>();
        commandList.add(executablePath);
        commandList.addAll(arguments);

        // Obfuscate passwords in telemetry if crackmapexec or ldapsearch
        record.command = sanitizeCommandForTelemetry(String.join(" ", commandList));
        record.args = sanitizeArgsForTelemetry(arguments);
        record.workingDir = System.getProperty("user.dir");

        long startTime = System.currentTimeMillis();
        Process process = null;

        StringBuilder outPreview = new StringBuilder();
        StringBuilder errPreview = new StringBuilder();
        StringBuilder fullOut = new StringBuilder();
        StringBuilder fullErr = new StringBuilder();

        try {
            ProcessBuilder pb = new ProcessBuilder(commandList);
            process = pb.start();
            record.status = "running";

            Process finalProcess = process;

            Thread outThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(finalProcess.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    int linesRead = 0;
                    while ((line = reader.readLine()) != null) {
                        fullOut.append(line).append("\n");
                        if (stdOutProcessor != null) stdOutProcessor.accept(line);
                        if (linesRead < 20) outPreview.append(line).append("\n");
                        linesRead++;
                    }
                } catch (IOException ignored) {}
            });

            Thread errThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(finalProcess.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    int linesRead = 0;
                    while ((line = reader.readLine()) != null) {
                        fullErr.append(line).append("\n");
                        if (stdErrProcessor != null) stdErrProcessor.accept(line);
                        if (linesRead < 20) errPreview.append(line).append("\n");
                        linesRead++;
                    }
                } catch (IOException ignored) {}
            });

            outThread.start();
            errThread.start();

            boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                record.timedOut = true;
                record.status = "timeout";
                process.destroyForcibly();
            } else {
                record.exitCode = process.exitValue();
                record.status = record.exitCode == 0 ? "success" : "failed";
            }

            outThread.join(2000);
            errThread.join(2000);

        } catch (InterruptedException e) {
            record.status = "cancelled";
            Thread.currentThread().interrupt();
            throw new java.util.concurrent.CancellationException("Execution cancelled by user.");
        } catch (Exception e) {
            record.status = "error";
            errPreview.append(e.getMessage());
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            record.durationMs = System.currentTimeMillis() - startTime;
            record.stdoutPreview = outPreview.toString();
            record.stderrPreview = errPreview.toString();
            record.stdout = fullOut.toString();
            record.stderr = fullErr.toString();
        }

        persistLogArtifact(toolId, "stdout", record.stdout);
        if (!record.stderr.isBlank()) persistLogArtifact(toolId, "stderr", record.stderr);

        return record;
    }

    private static String sanitizeCommandForTelemetry(String cmd) {
        if (cmd == null) return "";
        return cmd.replaceAll("-w\\s+\\S+", "-w *****")
                  .replaceAll("-p\\s+\\S+", "-p *****")
                  .replaceAll("-U\\s+\\S+", "-U *****");
    }

    private static List<String> sanitizeArgsForTelemetry(List<String> args) {
        List<String> clean = new ArrayList<>();
        boolean skipNext = false;
        for (String arg : args) {
            if (skipNext) {
                clean.add("*****");
                skipNext = false;
                continue;
            }
            if (arg.equals("-w") || arg.equals("-p")) {
                clean.add(arg);
                skipNext = true;
                continue;
            }
            if (arg.startsWith("-U") && arg.contains("%")) {
                int idx = arg.indexOf('%');
                clean.add(arg.substring(0, idx) + "%*****" + arg.substring(arg.lastIndexOf('"') == arg.length() - 1 ? arg.length() - 1 : arg.length()));
                continue;
            }
            clean.add(arg);
        }
        return clean;
    }

    private static void persistLogArtifact(String toolId, String stream, String content) {
        if (content == null || content.isBlank()) return;
        try {
            Path outputDir = Path.of(System.getProperty("user.dir", "."), "jabber-core/reports/outputs");
            Files.createDirectories(outputDir);
            String ts = String.valueOf(System.currentTimeMillis() / 1000);
            Path logFile = outputDir.resolve(toolId + "_" + ts + "_" + stream + ".log");
            Files.writeString(logFile, content, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception ignored) {}
    }
}
