package com.kitchome.auth.Exception;

import com.kitchome.auth.util.ErrorCode;
import com.kitchome.common.exception.BaseException;
import com.kitchome.common.util.ErrorSeverity;

public class AuthException extends BaseException {

    public AuthException(ErrorCode errorCode) {
        super(errorCode.name(), errorCode.getErrorCode(), ErrorSeverity.HIGH);
    }

    public AuthException(ErrorCode errorCode, String message) {
        super(message, errorCode.getErrorCode(), ErrorSeverity.HIGH);
    }

    public AuthException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.name(), errorCode.getErrorCode(), ErrorSeverity.HIGH, cause);
    }

    public AuthException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, errorCode.getErrorCode(), ErrorSeverity.HIGH, cause);
    }
}
