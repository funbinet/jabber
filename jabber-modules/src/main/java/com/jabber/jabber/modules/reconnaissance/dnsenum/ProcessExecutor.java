package com.jabber.jabber.modules.reconnaissance.dnsenum;

import com.jabber.jabber.data.model.TaskContext;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class ProcessExecutor {
    public CommandRecord execute(String toolId, List<String> command, TaskContext ctx, long timeoutMs) {
        long start = System.currentTimeMillis();
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Process p = pb.start();
            StringBuilder out = new StringBuilder(), err = new StringBuilder();

            Thread t1 = Thread.ofVirtual().start(() -> read(p.getInputStream(), out, ctx));
            Thread t2 = Thread.ofVirtual().start(() -> read(p.getErrorStream(), err, null));

            boolean done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!done) {
                p.destroyForcibly();
                return CommandRecord.timeout(toolId, command, System.currentTimeMillis() - start);
            }
            return new CommandRecord(toolId, command, p.exitValue(), out.toString(), err.toString(), System.currentTimeMillis() - start);
        } catch (Exception e) {
            return CommandRecord.error(toolId, command, e.getMessage(), System.currentTimeMillis() - start);
        }
    }

    private void read(InputStream s, StringBuilder sb, TaskContext ctx) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(s))) {
            String l;
            while ((l = r.readLine()) != null) {
                sb.append(l).append('\n');
                if (ctx != null) ctx.log("[" + l + "]");
            }
        } catch (IOException ignored) {}
    }
}
