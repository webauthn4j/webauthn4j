package net.sharplab.springframework.security.webauthn.exception;

public class MetadataException extends RuntimeException {
    public MetadataException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public MetadataException(String msg) {
        super(msg);
    }

    public MetadataException(Throwable cause) {
        super(cause);
    }

}