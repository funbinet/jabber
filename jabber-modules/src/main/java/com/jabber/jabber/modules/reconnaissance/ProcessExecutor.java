package com.jabber.jabber.modules.reconnaissance;

import com.jabber.jabber.data.model.TaskContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class ProcessExecutor {

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
        
        record.command = String.join(" ", commandList);
        record.args = new ArrayList<>(arguments);
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
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(finalProcess.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    int linesRead = 0;
                    while ((line = reader.readLine()) != null) {
                        fullOut.append(line).append("\n");
                        if (stdOutProcessor != null) {
                            stdOutProcessor.accept(line);
                        }
                        if (linesRead < 20) {
                            outPreview.append(line).append("\n");
                        }
                        linesRead++;
                    }
                } catch (IOException ignored) {}
            });

            Thread errThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(finalProcess.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    int linesRead = 0;
                    while ((line = reader.readLine()) != null) {
                        fullErr.append(line).append("\n");
                        if (stdErrProcessor != null) {
                            stdErrProcessor.accept(line);
                        }
                        if (linesRead < 20) {
                            errPreview.append(line).append("\n");
                        }
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

        } catch (Exception e) {
            record.status = "error";
            errPreview.append(e.getMessage());
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
            record.durationMs = System.currentTimeMillis() - startTime;
            record.stdoutPreview = outPreview.toString();
            record.stderrPreview = errPreview.toString();
            record.stdout = fullOut.toString();
            record.stderr = fullErr.toString();
        }

        return record;
    }
}
