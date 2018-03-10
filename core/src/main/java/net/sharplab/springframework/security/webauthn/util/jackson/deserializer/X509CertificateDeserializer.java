package net.sharplab.springframework.security.webauthn.util.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * Jackson Deserializer for X509Certificate
 */
public class X509CertificateDeserializer extends StdDeserializer<X509Certificate> {


    public X509CertificateDeserializer() {
        super(X509Certificate.class);
    }

    @Override
    public X509Certificate deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] value = p.getBinaryValue();
        if(value.length == 0){
            return null;
        }
        return CertificateUtil.generateX509Certificate(value);
    }
}
