package com.kitchome.auth.Exception;

import com.kitchome.common.exception.BaseException;
import com.kitchome.common.exception.ValidationError;
import com.kitchome.common.exception.ValidationException;
import com.kitchome.common.payload.ApiResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void testHandleMethodArgumentNotValid() throws NoSuchMethodException {
        java.lang.reflect.Method method = this.getClass().getDeclaredMethod("setUp");
        MethodParameter parameter = new MethodParameter(method, -1);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError = new FieldError("objectName", "field", "defaultMessage");
        when(bindingResult.getFieldErrors()).thenReturn(List.of(fieldError));

        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, bindingResult);

        ResponseEntity<Object> response = exceptionHandler.handleMethodArgumentNotValid(
                ex, new HttpHeaders(), HttpStatus.BAD_REQUEST, null);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ApiResponse<?> apiResponse = (ApiResponse<?>) response.getBody();
        assertNotNull(apiResponse);
        assertEquals("Input validation failed", apiResponse.getMessage());
        List<ValidationError> errors = (List<ValidationError>) apiResponse.getPayload();
        assertEquals(1, errors.size());
        assertEquals("field", errors.get(0).getFieldName());
        assertEquals("defaultMessage", errors.get(0).getMessage());
    }

    @Test
    void testHandleBaseException() {
        BaseException ex = new BaseException("Base error message", "BASE_ERR");
        ResponseEntity<ApiResponse<?>> response = exceptionHandler.handleBaseException(ex);

        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Base error message", response.getBody().getMessage());
    }

    @Test
    void testHandleValidationException() {
        List<ValidationError> errors = List.of(ValidationError.builder().fieldName("f1").message("m1").build());
        ValidationException ex = new ValidationException("Validation failed test", "VAL_FAIL_TEST", errors);
        ResponseEntity<ApiResponse<?>> response = exceptionHandler.handleValidationException(ex);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Validation failed test", response.getBody().getMessage());
        List<ValidationError> valErrors = (List<ValidationError>) response.getBody().getPayload();
        assertEquals(1, valErrors.size());
    }

    @Test
    void testHandleAccessDeniedException() {
        AccessDeniedException ex = new AccessDeniedException("Access denied message");
        ResponseEntity<ApiResponse<?>> response = exceptionHandler.handleAccessDeniedException(ex);

        assertNotNull(response);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("Access Denied", response.getBody().getMessage());
    }

    @Test
    void testHandleAuthenticationException() {
        AuthenticationException ex = new AuthenticationException("Auth error") {};
        ResponseEntity<ApiResponse<?>> response = exceptionHandler.handleAuthenticationException(ex);

        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Authentication Failed", response.getBody().getMessage());
    }

    @Test
    void testHandleGeneralException() {
        Exception ex = new Exception("General error");
        ResponseEntity<ApiResponse<?>> response = exceptionHandler.handleGeneralException(ex);

        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("An unexpected error occurred", response.getBody().getMessage());
    }
}
