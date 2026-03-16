package com.kitchome.common.exception;

import com.kitchome.common.util.ErrorSeverity;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

/**
 * Exception thrown when validation fails.
 */
@Getter
public class ValidationException extends BaseException {

    private final List<ValidationError> errors;

    public ValidationException(String message, String errorCode) {
        this(message, errorCode, new ArrayList<>());
    }

    public ValidationException(String message, String errorCode, List<ValidationError> errors) {
        super(message, errorCode, ErrorSeverity.NORMAL);
        this.errors = errors;
    }

    public void addError(ValidationError error) {
        this.errors.add(error);
    }
}
