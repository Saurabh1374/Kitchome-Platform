package com.kitchome.auth.payload;

import java.util.Arrays;
import java.util.List;
import com.kitchome.common.exception.ValidationError;

public class ValidationResult {

	private List<ValidationError> validationError;

	public ValidationResult(ValidationError... validationError) {
		if (validationError != null) {
			this.validationError = Arrays.asList(validationError);
		}
	}

	public List<ValidationError> getValidationError() {
		return validationError;
	}

	public boolean isvalid() {
		return this.validationError == null || this.validationError.isEmpty();
	}

}
