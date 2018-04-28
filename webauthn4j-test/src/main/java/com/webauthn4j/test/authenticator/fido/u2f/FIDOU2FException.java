package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.util.WIP;

@WIP
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
