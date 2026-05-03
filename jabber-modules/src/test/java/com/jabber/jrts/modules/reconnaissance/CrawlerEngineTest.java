package com.jabber.jabber.modules.reconnaissance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CrawlerEngineTest {

    @Test
    void extractsUrlsFromToolOutput() {
        String line = "Found: https://example.com/login, see https://example.com/api?q=1).";
        List<String> urls = CrawlerEngine.extractUrlsFromText(line);

        assertEquals(2, urls.size());
        assertTrue(urls.contains("https://example.com/login"));
        assertTrue(urls.contains("https://example.com/api?q=1"));
    }
}
