package com.webauthn4j.data.internal.asn1.der;

import java.math.BigInteger;

/**
 * DER-encoded ASN.1 INTEGER element.
 */
public class ASN1Integer extends ASN1Primitive {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.INTEGER);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1Integer(ASN1Length length, byte[] value) {
        super(TAG, length, value);
    }

    /**
     * Constructor for programmatic construction.
     */
    ASN1Integer(byte[] value) {
        super(TAG, value);
    }

    /**
     * Parse DER-encoded data as an INTEGER element.
     *
     * @param bytes DER-encoded data
     * @return ASN1Integer instance
     */
    public static ASN1Integer parse(byte[] bytes) {
        return (ASN1Integer) ASN1.parse(bytes);
    }

    /**
     * Create an INTEGER element.
     *
     * @param value two's complement integer value bytes
     * @return ASN1Integer instance
     */
    public static ASN1Integer create(byte[] value) {
        return new ASN1Integer(value);
    }

    /**
     * Returns the integer value.
     *
     * @return BigInteger decoded from two's complement representation
     */
    public BigInteger getContent() {
        return new BigInteger(getValue());
    }
}
