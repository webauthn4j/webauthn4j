package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

import java.security.cert.X509Certificate;

public class CertPathException extends VerificationException {

    private final X509Certificate certificate;

    public CertPathException(@Nullable String message, @Nullable X509Certificate certificate, @Nullable Throwable cause) {
        super(message, cause);
        this.certificate = certificate;
    }

    public CertPathException(@Nullable String message, @Nullable X509Certificate certificate) {
        super(message);
        this.certificate = certificate;
    }

    public CertPathException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.certificate = null;
    }

    public CertPathException(@Nullable String message) {
        super(message);
        this.certificate = null;
    }

    public CertPathException(@Nullable Throwable cause) {
        super(cause);
        this.certificate = null;
    }

    @Nullable
    public X509Certificate getCertificate() {
        return certificate;
    }
}
