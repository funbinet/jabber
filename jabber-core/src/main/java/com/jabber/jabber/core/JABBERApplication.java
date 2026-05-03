package com.jabber.jabber.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * JABBER V 5.5.0 - Core Application
 *
 * Production-grade, modular offensive security operations platform.
 * Dual-runtime: Spring Boot Web API + Electron Native Desktop.
 * Created by Funbinet (dancan.tech)
 */
@SpringBootApplication
@EnableAsync
@ComponentScan(basePackages = {"com.jabber.jabber"})
@EntityScan(basePackages = {"com.jabber.jabber"})
public class JABBERApplication {

    public static void main(String[] args) {
        System.setProperty("spring.application.name", "JABBER V 5.5.0");
        SpringApplication.run(JABBERApplication.class, args);
    }
}
