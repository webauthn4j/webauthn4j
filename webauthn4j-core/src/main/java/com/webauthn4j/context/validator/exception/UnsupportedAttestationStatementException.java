package com.webauthn4j.context.validator.exception;

public class UnsupportedAttestationStatementException extends ValidationException {
    public UnsupportedAttestationStatementException(String message) {
        super(message);
    }

    public UnsupportedAttestationStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}