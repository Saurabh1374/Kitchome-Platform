package com.kitchome.common.payload;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

import com.kitchome.common.exception.ValidationError;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.kitchome.common.util.Constants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * Standard API response wrapper for the KitChome ecosystem.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> implements Serializable {
    private static final long serialVersionUID = 1L;

    private String message;
    private String status;
    private String errorCode;
    private Integer httpStatus;
    private LocalDateTime timestamp;
    private String correlationId;
    private String traceId;

    // Pagination fields
    private Long totalCount;
    private Integer pages;
    private Integer pageNumber;

    /**
     * Payload is marked transient for enhanced security during Java serialization.
     * Jackson will still serialize this to JSON by default.
     */
    private transient T payload;

    @JsonProperty("payload")
    public T getPayload() {
        return payload;
    }

    @JsonProperty("payload")
    public void setPayload(T payload) {
        this.payload = payload;
    }

    // --- Static Factory Methods ---

    public static <T> ApiResponse<T> success(T payload) {
        return success(payload, "Operation successful");
    }

    public static <T> ApiResponse<T> success(T payload, String message) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setStatus(Constants.SUCCESS);
        response.setMessage(message);
        response.setHttpStatus(HttpStatus.OK.value());
        response.setPayload(payload);
        response.setTimestamp(LocalDateTime.now());
        return response;
    }

    public static <T> ApiResponse<T> success(T payload, Long totalCount, Integer pages, Integer pageNumber) {
        ApiResponse<T> response = success(payload);
        response.setTotalCount(totalCount);
        response.setPages(pages);
        response.setPageNumber(pageNumber);
        return response;
    }

    public static <T> ApiResponse<T> error(String message, String errorCode, HttpStatus httpStatus) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setStatus(Constants.ERROR);
        response.setMessage(message);
        response.setErrorCode(errorCode);
        response.setHttpStatus(httpStatus.value());
        response.setTimestamp(LocalDateTime.now());
        return response;
    }

    public static ApiResponse<List<ValidationError>> error(List<ValidationError> errors, String message,
            String errorCode) {
        ApiResponse<List<ValidationError>> response = error(message, errorCode, HttpStatus.BAD_REQUEST);
        response.setPayload(errors);
        return response;
    }
}
