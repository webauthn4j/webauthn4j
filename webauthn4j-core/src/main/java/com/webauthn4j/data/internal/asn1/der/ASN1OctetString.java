package com.webauthn4j.data.internal.asn1.der;

/**
 * DER-encoded ASN.1 OCTET STRING element.
 */
public class ASN1OctetString extends ASN1Primitive {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.OCTET_STRING);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1OctetString(ASN1Length length, byte[] value) {
        super(TAG, length, value);
    }

    /**
     * Constructor for programmatic construction.
     */
    ASN1OctetString(byte[] value) {
        super(TAG, value);
    }

    /**
     * Parse DER-encoded data as an OCTET STRING element.
     *
     * @param bytes DER-encoded data
     * @return ASN1OctetString instance
     */
    public static ASN1OctetString parse(byte[] bytes) {
        return (ASN1OctetString) ASN1.parse(bytes);
    }

    /**
     * Create an OCTET STRING element.
     *
     * @param value raw octet string content
     * @return ASN1OctetString instance
     */
    public static ASN1OctetString create(byte[] value) {
        return new ASN1OctetString(value);
    }
}
