package com.kitchome.common.exception;

import static com.kitchome.common.util.Constants.CALLED;
import static com.kitchome.common.util.Constants.EXCEPTION_LOG_FORMAT;

import com.kitchome.common.payload.ApiResponse;
import com.kitchome.common.util.ErrorSeverity;
import io.micrometer.tracing.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

/**
 * Base exception handler utility providing reusable logic for service-specific
 * ControllerAdvice.
 */
@Slf4j
public abstract class BaseExceptionHandler extends ResponseEntityExceptionHandler {

    @Autowired(required = false)
    private Tracer tracer;

    /**
     * Helper to build a standardized ApiResponse error (without payload for
     * security).
     */
    protected ResponseEntity<ApiResponse<Object>> buildErrorResponse(String message, String errorCode,
            HttpStatus status) {
        ApiResponse<Object> response = ApiResponse.error(message, errorCode, status);
        populateTraceId(response);
        return new ResponseEntity<>(response, status);
    }

    /**
     * Helper to build a standardized validation error response.
     */
    protected ResponseEntity<ApiResponse<List<ValidationError>>> buildValidationErrorResponse(
            List<ValidationError> errors, String message, String errorCode) {
        ApiResponse<List<ValidationError>> response = ApiResponse.error(errors, message, errorCode);
        populateTraceId(response);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    private void populateTraceId(ApiResponse<?> response) {
        if (tracer != null && tracer.currentSpan() != null) {
            response.setTraceId(tracer.currentSpan().context().traceId());
        }
    }

    /**
     * Helper to log exceptions based on severity.
     */
    protected <T extends BaseException> void logBySeverity(T ex) {
        log.debug(CALLED);

        ErrorSeverity severity = (ex.getSeverity() != null) ? ex.getSeverity() : ErrorSeverity.NORMAL;
        String severityName = severity.name();
        String className = ex.getClass().getSimpleName();
        String errorCode = ex.getErrorCode();
        String message = ex.getMessage();

        if (severity == ErrorSeverity.BLOCKER) {
            log.error(EXCEPTION_LOG_FORMAT, severityName, className, errorCode, message);
        } else {
            log.warn(EXCEPTION_LOG_FORMAT, severityName, className, errorCode, message);
        }
    }
}