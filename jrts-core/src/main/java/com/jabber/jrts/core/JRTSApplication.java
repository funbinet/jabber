package com.jabber.jrts.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * JABBER Red Teaming Suite V2 - Core Application
 *
 * Production-grade, modular offensive security operations platform.
 * Dual-runtime: Spring Boot Web API + Electron Native Desktop.
 * Created by Funbinet (dancan.tech)
 */
@SpringBootApplication
@EnableAsync
@ComponentScan(basePackages = {"com.jabber.jrts"})
@EntityScan(basePackages = {"com.jabber.jrts"})
public class JRTSApplication {

    public static void main(String[] args) {
        System.setProperty("spring.application.name", "JRTS V2 - Jabber Red Teaming Suite");
        SpringApplication.run(JRTSApplication.class, args);
    }
}
