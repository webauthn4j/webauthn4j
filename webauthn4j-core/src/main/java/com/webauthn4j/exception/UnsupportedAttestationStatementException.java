package com.webauthn4j.exception;

public class UnsupportedAttestationStatementException extends ValidationException {
    public UnsupportedAttestationStatementException(String message) {
        super(message);
    }

    public UnsupportedAttestationStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}