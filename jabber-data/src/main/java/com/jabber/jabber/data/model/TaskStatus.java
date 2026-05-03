package com.jabber.jabber.data.model;

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
