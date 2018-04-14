package com.webauthn4j.exception;

/**
 * An exception expected not to be thrown
 */
public class UnexpectedCheckedException extends RuntimeException {
    public UnexpectedCheckedException(Throwable throwable){
        super(throwable);
    }
}
