package com.jabber.jabber.data.model;

import java.lang.annotation.*;

/**
 * Annotation to mark a class as a JABBER security module.
 * The plugin registry scans for this annotation to auto-discover modules.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface JABBERModule {
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
    String version() default "V5.5";

    /** Module author */
    String author() default "JABBER";

    /** Reference to original frags script if applicable */
    String sourceRef() default "";
}
