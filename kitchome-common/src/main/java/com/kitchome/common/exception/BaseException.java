package com.kitchome.common.exception;

import com.kitchome.common.util.ErrorSeverity;
import lombok.Getter;

/**
 * Base custom runtime exception for the KitChome ecosystem.
 */
@Getter
public class BaseException extends RuntimeException {

    private final String errorCode;
    private final ErrorSeverity severity;
    private final String errorMessage;
    private final Throwable throwable;

    public BaseException(String message, String errorCode) {
        this(message, errorCode, ErrorSeverity.NORMAL);
    }

    public BaseException(String message, String errorCode, ErrorSeverity severity) {
        super(message);
        this.errorCode = errorCode;
        this.severity = severity;
        this.errorMessage = message;
        this.throwable = null;
    }

    public BaseException(String message, String errorCode, Throwable cause) {
        this(message, errorCode, ErrorSeverity.NORMAL, cause);
    }

    public BaseException(String message, String errorCode, ErrorSeverity severity, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.severity = severity;
        this.errorMessage = message;
        this.throwable = cause;
    }
}
