package com.webauthn4j.validator.exception;


/**
 * BadAttestationStatementException
 */
public class BadAttestationStatementException extends ValidationException {
    public BadAttestationStatementException(String message) {
        super(message);
    }

    public BadAttestationStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}