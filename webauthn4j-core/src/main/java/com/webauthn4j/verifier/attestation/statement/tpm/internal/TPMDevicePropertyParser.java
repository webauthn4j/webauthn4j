package com.webauthn4j.verifier.attestation.statement.tpm.internal;

import com.webauthn4j.data.internal.asn1.der.ASN1;
import com.webauthn4j.data.internal.asn1.der.ASN1ObjectIdentifier;
import com.webauthn4j.data.internal.asn1.der.ASN1OctetString;
import com.webauthn4j.data.internal.asn1.der.ASN1Primitive;
import com.webauthn4j.data.internal.asn1.der.ASN1Sequence;
import com.webauthn4j.data.internal.asn1.der.ASN1Structure;
import com.webauthn4j.data.internal.asn1.der.ASN1Utf8String;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDeviceProperty;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class TPMDevicePropertyParser {

    private static final String SAN_OID = "2.5.29.17";
    private static final String TPM_MANUFACTURER_OID = "2.23.133.2.1";
    private static final String TPM_PART_NUMBER_OID = "2.23.133.2.2";
    private static final String TPM_FIRMWARE_VERSION_OID = "2.23.133.2.3";
    private static final int GENERAL_NAME_DIRECTORY_NAME_TAG = 4;
    private static final int ASN1_TAG_UTF8_STRING = 0x0C;

    private TPMDevicePropertyParser() {
    }

    public static TPMDeviceProperty parse(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(SAN_OID);
        if (extensionValue == null) {
            throw new BadAttestationStatementException(
                    "The Subject Alternative Name extension is not present in the attestation certificate");
        }

        Map<String, String> attributes = parseDirectoryNameAttributes(extensionValue);

        String manufacturer = attributes.get(TPM_MANUFACTURER_OID);
        String partNumber = attributes.get(TPM_PART_NUMBER_OID);
        String firmwareVersion = attributes.get(TPM_FIRMWARE_VERSION_OID);
        return new TPMDeviceProperty(manufacturer, partNumber, firmwareVersion);
    }

    private static Map<String, String> parseDirectoryNameAttributes(byte[] extensionValue) {
        ASN1OctetString outerOctetString = ASN1OctetString.parse(extensionValue);
        ASN1Sequence generalNames = ASN1Sequence.parse(outerOctetString.getValue());

        for (ASN1 generalName : generalNames) {
            if (generalName.isConstructed() && generalName.getTagNumber() == GENERAL_NAME_DIRECTORY_NAME_TAG) {
                return parseRdnSequence((ASN1Structure) generalName);
            }
        }
        return Map.of();
    }

    private static Map<String, String> parseRdnSequence(ASN1Structure directoryName) {
        Map<String, String> attributes = new HashMap<>();
        ASN1Structure rdnSequence = (ASN1Structure) directoryName.get(0);

        for (ASN1 rdnElement : rdnSequence) {
            ASN1Structure rdn = (ASN1Structure) rdnElement;
            for (ASN1 attrElement : rdn) {
                ASN1Structure attributeTypeAndValue = (ASN1Structure) attrElement;
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.parse(attributeTypeAndValue.get(0).toBytes());
                ASN1 value = attributeTypeAndValue.get(1);
                attributes.put(oid.getContent(), decodeStringValue(value));
            }
        }
        return attributes;
    }

    private static String decodeStringValue(ASN1 value) {
        int tagNumber = value.getTagNumber();
        if (tagNumber == ASN1_TAG_UTF8_STRING) {
            return ASN1Utf8String.parse(value.toBytes()).getContent();
        }
        return new String(((ASN1Primitive) value).getValue(), StandardCharsets.US_ASCII);
    }
}
