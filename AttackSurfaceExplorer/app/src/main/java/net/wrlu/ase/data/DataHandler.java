package net.wrlu.ase.data;

import android.database.Cursor;

/**
 * Handles a single data endpoint exposed by {@link DataProvider}.
 *
 * <p>An endpoint is addressed by the first path segment of the query URI
 * (e.g. {@code content://net.wrlu.ase.probe/binder_service}). The optional caller
 * argument (service name, package name, ...) is resolved by {@link DataProvider}
 * and passed to {@link #query(String)} as {@code arg} ({@code null}/empty = all).
 */
public interface DataHandler {

    /** URI path segment that selects this handler, e.g. {@code binder_service}. */
    String path();

    /** Produce the data cursor for the given argument ({@code null}/empty = all entries). */
    Cursor query(String arg);
}
