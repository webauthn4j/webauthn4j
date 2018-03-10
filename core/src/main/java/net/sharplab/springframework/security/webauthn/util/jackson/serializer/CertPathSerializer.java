package net.sharplab.springframework.security.webauthn.util.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

/**
 * Jackson Serializer for CertPath
 */
public class CertPathSerializer extends StdSerializer<CertPath> {
    public CertPathSerializer() {
        super(CertPath.class);
    }

    @Override
    public void serialize(CertPath value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        try {
            gen.writeStartArray();
            for(Certificate certificate : value.getCertificates()){
                gen.writeBinary(certificate.getEncoded());
            }
            gen.writeEndArray();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }
}
