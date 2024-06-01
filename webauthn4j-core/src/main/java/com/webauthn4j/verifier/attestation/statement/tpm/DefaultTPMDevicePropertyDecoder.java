package com.webauthn4j.verifier.attestation.statement.tpm;

import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import org.apache.kerby.asn1.type.Asn1Utf8String;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultTPMDevicePropertyDecoder implements TPMDevicePropertyDecoder {

    public TPMDeviceProperty decode(String subjectAlternativeName) throws BadAttestationStatementException {
        try{
            Map<String, Object> map = parseSubjectAlternativeName(subjectAlternativeName);

            byte[] manufacturerAttr = (byte[]) map.get("2.23.133.2.1");
            byte[] partNumberAttr = (byte[]) map.get("2.23.133.2.2");
            byte[] firmwareVersionAttr = (byte[]) map.get("2.23.133.2.3");

            String manufacturer = decodeAttr(manufacturerAttr);
            String partNumber = decodeAttr(partNumberAttr);
            String firmwareVersion = decodeAttr(firmwareVersionAttr);
            return new TPMDeviceProperty(manufacturer, partNumber, firmwareVersion);
        }
        catch (IOException e) {
            throw new BadAttestationStatementException("The Subject Alternative Name extension of attestation certificate does not contain a TPM device property", e);
        }
    }

    public static String decodeAttr(byte[] attr) throws IOException {
        if (attr == null) {
            return null;
        }
        else {
            Asn1Utf8String attrAsn1Utf8String = new Asn1Utf8String();
            attrAsn1Utf8String.decode(attr);
            return attrAsn1Utf8String.getValue();
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
