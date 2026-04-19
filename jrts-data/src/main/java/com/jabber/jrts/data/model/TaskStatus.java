package com.jabber.jrts.data.model;

/**
 * Lifecycle states for an executing module task.
 */
public enum TaskStatus {
    QUEUED,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
}
