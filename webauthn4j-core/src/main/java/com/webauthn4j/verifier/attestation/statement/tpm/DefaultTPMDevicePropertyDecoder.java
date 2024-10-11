package com.webauthn4j.verifier.attestation.statement.tpm;

import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.internal.asn1.ASN1Primitive;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultTPMDevicePropertyDecoder implements TPMDevicePropertyDecoder {

    public TPMDeviceProperty decode(String subjectAlternativeName) throws BadAttestationStatementException {
        Map<String, Object> map = parseSubjectAlternativeName(subjectAlternativeName);

        byte[] manufacturerAttr = (byte[]) map.get("2.23.133.2.1");
        byte[] partNumberAttr = (byte[]) map.get("2.23.133.2.2");
        byte[] firmwareVersionAttr = (byte[]) map.get("2.23.133.2.3");

        String manufacturer = decodeAttr(manufacturerAttr);
        String partNumber = decodeAttr(partNumberAttr);
        String firmwareVersion = decodeAttr(firmwareVersionAttr);
        return new TPMDeviceProperty(manufacturer, partNumber, firmwareVersion);
    }

    public static String decodeAttr(byte[] attr) {
        if (attr == null) {
            return null;
        }
        else {
            ASN1Primitive asn1Primitive = ASN1Primitive.parse(attr);
            return asn1Primitive.getValueAsUtf8String();
        }
    }

    private static Map<String, Object> parseSubjectAlternativeName(String subjectAlternativeName){
        LdapName subjectDN;
        try {
            subjectDN = new LdapName(subjectAlternativeName);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e);
        }
        return subjectDN.getRdns().stream().flatMap(rdn -> convertRdnToMap(rdn).entrySet().stream()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static Map<String, Object> convertRdnToMap(Rdn rdn) {
        try {
            Map<String, Object> map = new HashMap<>();
            Attributes attributes = rdn.toAttributes();
            NamingEnumeration<String> ids = rdn.toAttributes().getIDs();

            while (ids.hasMore()) {
                String id = ids.next();
                map.put(id, attributes.get(id).get());
            }
            return map;

        } catch (NamingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
