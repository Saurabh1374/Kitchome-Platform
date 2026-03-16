package com.kitchome.auth.Exception;

import com.kitchome.common.exception.BaseException;
import com.kitchome.common.exception.BaseExceptionHandler;
import com.kitchome.common.exception.ValidationError;
import com.kitchome.common.exception.ValidationException;
import com.kitchome.common.payload.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler extends BaseExceptionHandler {

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(
			MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {

		log.error("MethodArgumentNotValidException occurred: {}", ex.getMessage());

		List<ValidationError> validationErrors = ex.getBindingResult()
				.getFieldErrors()
				.stream()
				.map(error -> ValidationError.builder()
						.fieldName(error.getField())
						.message(error.getDefaultMessage())
						.errorCode("INVALID_FIELD")
						.build())
				.collect(Collectors.toList());

		return (ResponseEntity) buildValidationErrorResponse(validationErrors, "Input validation failed",
				"VALIDATION_FAILED");
	}

	@ExceptionHandler(BaseException.class)
	public ResponseEntity<ApiResponse<?>> handleBaseException(BaseException ex) {
		logBySeverity(ex);
		return (ResponseEntity) buildErrorResponse(ex.getMessage(), ex.getErrorCode(),
				HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(ValidationException.class)
	public ResponseEntity<ApiResponse<?>> handleValidationException(ValidationException ex) {
		logBySeverity(ex);
		return (ResponseEntity) buildValidationErrorResponse(ex.getErrors(), ex.getMessage(), ex.getErrorCode());
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiResponse<?>> handleAccessDeniedException(AccessDeniedException ex) {
		log.error("Access Denied: {}", ex.getMessage());
		return (ResponseEntity) buildErrorResponse("Access Denied", "ACCESS_DENIED", HttpStatus.FORBIDDEN);
	}

	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<ApiResponse<?>> handleAuthenticationException(AuthenticationException ex) {
		log.error("Authentication Error: {}", ex.getMessage());
		return (ResponseEntity) buildErrorResponse("Authentication Failed", "AUTH_FAILED", HttpStatus.UNAUTHORIZED);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiResponse<?>> handleGeneralException(Exception ex) {
		log.error("Unexpected exception occurred", ex);
		return (ResponseEntity) buildErrorResponse("An unexpected error occurred", "INTERNAL_SERVER_ERROR",
				HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
