package com.webauthn4j.metadata.converter.jackson.deserializer;

import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.security.cert.X509Certificate;

public class MetadataX509CertificateRelaxedDeserializer extends StdDeserializer<X509Certificate> {


    public MetadataX509CertificateRelaxedDeserializer() {
        super(X509Certificate.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @Nullable X509Certificate deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString().trim().replace("\r", "").replace("\n", ""); //trimming added
        byte[] bytes = Base64Util.decode(value);
        if (bytes.length == 0) {
            return null;
        }
        return CertificateUtil.generateX509Certificate(bytes);
    }
}
