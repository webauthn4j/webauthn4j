package net.sharplab.springframework.security.webauthn.util.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Jackson Serializer for X509Certificate
 */
public class X509CertificateSerializer extends StdSerializer<X509Certificate> {

    public X509CertificateSerializer() {
        super(X509Certificate.class);
    }

    @Override
    public void serialize(X509Certificate value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        try {
            gen.writeBinary(value.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }
}
