package com.kitchome.auth.payload.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.kitchome.common.exception.ValidationError;
import com.kitchome.auth.util.ErrorCode;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
public class ErrorResponse {
    private ErrorCode errorCode;
    private String errorMessage;
    private List<ValidationError> errorValidation;

    @JsonCreator
    public ErrorResponse(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public ErrorResponse(ErrorCode errorCode, String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public static ErrorResponse of(ErrorCode errorCode) {
        return new ErrorResponse(errorCode);
    }

    public static ErrorResponse of(ErrorCode errorCode, String errorMessage) {
        return new ErrorResponse(errorCode, errorMessage);
    }
}
