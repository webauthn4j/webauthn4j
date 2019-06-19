package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.X509CertificateDeserializer;
import com.webauthn4j.converter.jackson.serializer.X509CertificateSerializer;

import java.security.cert.X509Certificate;

public final class WebAuthnJWSModule extends SimpleModule {
    public WebAuthnJWSModule() {
        super("WebAuthnJWSModule");

        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());
    }
}
