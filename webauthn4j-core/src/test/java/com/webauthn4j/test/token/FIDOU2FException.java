package com.webauthn4j.test.token;

public class FIDOU2FException extends RuntimeException{

    public FIDOU2FException(String message, Throwable cause) {
        super(message, cause);
    }

    public FIDOU2FException(Throwable cause) {
        super(cause);
    }

    public FIDOU2FException(String message) {
        super(message);
    }
}
