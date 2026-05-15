package com.webauthn4j.data.internal.asn1.der;

/**
 * Base class for DER-encoded ASN.1 primitive (non-constructed) elements.
 * <p>
 * For known UNIVERSAL types, the parser returns type-specific subclasses
 * ({@link ASN1Integer}, {@link ASN1BitString}, {@link ASN1OctetString}, {@link ASN1ObjectIdentifier}).
 * For unknown or context-specific types, this class is used directly.
 * <p>
 * Use {@link ASN1#parse(byte[])} to parse DER-encoded data.
 */
public class ASN1Primitive extends ASN1 {

    private final byte[] value;

    /**
     * Constructor for parsed data — preserves the original T, L, V.
     */
    ASN1Primitive(ASN1Tag tag, ASN1Length length, byte[] value) {
        super(tag, length);
        this.value = value.clone();
    }

    /**
     * Constructor for programmatic construction — L is computed from V.
     */
    ASN1Primitive(ASN1Tag tag, byte[] value) {
        super(tag, value.length);
        this.value = value.clone();
    }

    /**
     * Returns a copy of the value bytes (the V part of TLV).
     *
     * @return value bytes
     */
    @Override
    public byte[] getValue() {
        return value.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ASN1Primitive that = (ASN1Primitive) o;
        return java.util.Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(value);
    }
}
