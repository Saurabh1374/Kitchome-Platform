package com.kitchome.common.util;

/**
 * Utility class for shared constants.
 */
public final class Constants {

    private Constants() {
        // Private constructor to prevent instantiation
    }

    public static final String SUCCESS = "SUCCESS";
    public static final String ERROR = "ERROR";
    public static final String EXCEPTION_LOG_FORMAT = "Exception severity: {}, Exception class: {}, Exception code: {}, Exception message: {}";
    public static final String CALLED = "CALLED";
    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
}
