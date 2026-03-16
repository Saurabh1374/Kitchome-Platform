package com.kitchome.auth.util;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
	VALIDATION_ERROR("KIC-11000", HttpStatus.BAD_REQUEST),
	USER_ALREADY_AVAILABLE("KIC-10000", HttpStatus.CONFLICT),
	INTERNAL_SERVER_ERROR("KIC-12000", HttpStatus.INTERNAL_SERVER_ERROR),
	SUSPESIOUS("KIC-11111", HttpStatus.BAD_REQUEST),
	TOKEN_NOT_FOUND("KIC-110404", HttpStatus.BAD_REQUEST),
	TOKEN_EXPIRED("KIC-110410", HttpStatus.GONE);

	private String ErrorCode;
	private HttpStatus httpStatus;

	ErrorCode(String errorCode, HttpStatus httpStatus) {
		ErrorCode = errorCode;
		this.httpStatus = httpStatus;
	}

	public String getErrorCode() {
		return this.ErrorCode;
	}

	public HttpStatus getHttpStatus() {
		return httpStatus;
	}
}
