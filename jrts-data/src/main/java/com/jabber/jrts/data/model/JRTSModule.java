package com.jabber.jrts.data.model;

import java.lang.annotation.*;

/**
 * Annotation to mark a class as a JRTS security module.
 * The plugin registry scans for this annotation to auto-discover modules.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface JRTSModule {
    /** Unique module identifier */
    String id();

    /** Human-readable module name */
    String name();

    /** Module description */
    String description();

    /** Attack lifecycle category */
    Category category();

    /** Risk level classification */
    RiskLevel riskLevel();

    /** Module version */
    String version() default "1.0.0";

    /** Module author */
    String author() default "JRTS";

    /** Reference to original frags script if applicable */
    String sourceRef() default "";
}
