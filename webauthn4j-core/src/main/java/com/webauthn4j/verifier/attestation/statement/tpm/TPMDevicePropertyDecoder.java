package com.webauthn4j.verifier.attestation.statement.tpm;

import org.jetbrains.annotations.Nullable;

public interface TPMDevicePropertyDecoder {

    TPMDeviceProperty decode(String subjectAlternativeName) throws TPMDevicePropertyDecoderException;

    public class TPMDevicePropertyDecoderException extends RuntimeException{
        protected TPMDevicePropertyDecoderException(@Nullable String message, @Nullable Throwable cause) {
            super(message, cause);
        }

        protected TPMDevicePropertyDecoderException(@Nullable String message) {
            super(message);
        }

        protected TPMDevicePropertyDecoderException(@Nullable Throwable cause) {
            super(cause);
        }
    }
}
