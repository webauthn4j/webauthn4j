package com.webauthn4j.metadata.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class MetadataX509CertificateRelaxedDeserializer extends StdDeserializer<X509Certificate> {


    public MetadataX509CertificateRelaxedDeserializer() {
        super(X509Certificate.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @Nullable X509Certificate deserialize(@NonNull JsonParser p, @NonNull DeserializationContext ctxt) throws IOException {
        String value = p.getValueAsString().trim(); //trimming added
        byte[] bytes = Base64Util.decode(value);
        if (bytes.length == 0) {
            return null;
        }
        return CertificateUtil.generateX509Certificate(bytes);
    }
}
