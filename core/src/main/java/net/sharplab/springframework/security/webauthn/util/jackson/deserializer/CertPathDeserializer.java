package net.sharplab.springframework.security.webauthn.util.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;

import java.io.IOException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Jackson Deserializer for CertPath
 */
public class CertPathDeserializer extends StdDeserializer<CertPath> {

    public CertPathDeserializer() {
        super(CertPath.class);
    }

    @Override
    public CertPath deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        ObjectCodec oc = p.getCodec();
        ArrayNode node = oc.readTree(p);
        List<Certificate> list = new ArrayList<>();
        for(JsonNode item : node){
            X509Certificate certificate = oc.treeToValue(item, X509Certificate.class);
            list.add(certificate);
        }
        return CertificateUtil.generateCertPath(list);
    }
}
