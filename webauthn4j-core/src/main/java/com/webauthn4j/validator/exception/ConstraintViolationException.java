package com.webauthn4j.validator.exception;

import javax.validation.ConstraintViolation;
import java.util.Set;

public class ConstraintViolationException extends ValidationException {

    private Set<ConstraintViolation> constraintViolations;

    public ConstraintViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConstraintViolationException(String message) {
        super(message);
    }

    public ConstraintViolationException(String message, Set<ConstraintViolation> constraintViolations) {
        super(message);
        this.constraintViolations = constraintViolations;
    }

    public Set<ConstraintViolation> getConstraintViolations() {
        return constraintViolations;
    }
}
