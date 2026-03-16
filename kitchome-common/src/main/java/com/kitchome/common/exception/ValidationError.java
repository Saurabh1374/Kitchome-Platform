package com.kitchome.common.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Data class to hold field-specific validation errors.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidationError implements Serializable {
    private static final long serialVersionUID = 1L;

    private String fieldName;
    private String message;
    private String errorCode;
}
