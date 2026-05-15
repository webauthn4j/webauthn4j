package com.webauthn4j.data.internal.asn1.der;

import java.nio.charset.StandardCharsets;

/**
 * DER-encoded ASN.1 UTF8String element.
 */
public class ASN1Utf8String extends ASN1Primitive {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.UTF8_STRING);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1Utf8String(ASN1Length length, byte[] value) {
        super(TAG, length, value);
    }

    /**
     * Parse DER-encoded data as a UTF8String element.
     *
     * @param bytes DER-encoded data
     * @return ASN1Utf8String instance
     */
    public static ASN1Utf8String parse(byte[] bytes) {
        return (ASN1Utf8String) ASN1.parse(bytes);
    }

    /**
     * Returns the string content.
     *
     * @return decoded UTF-8 string
     */
    public String getContent() {
        return new String(getValue(), StandardCharsets.UTF_8);
    }
}
