package com.webauthn4j.data.internal.asn1.der;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.util.Arrays;

/**
 * DER-encoded ASN.1 BIT STRING element.
 * <p>
 * The raw value (from TLV) includes an "unused bits" prefix byte.
 * Use {@link #getContent()} to get the actual bit data without the prefix.
 */
public class ASN1BitString extends ASN1Primitive {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.BIT_STRING);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1BitString(ASN1Length length, byte[] value) {
        super(TAG, length, value);
    }

    /**
     * Constructor for programmatic construction.
     */
    ASN1BitString(byte[] value) {
        super(TAG, value);
    }

    /**
     * Parse DER-encoded data as a BIT STRING element.
     *
     * @param bytes DER-encoded data
     * @return ASN1BitString instance
     */
    public static ASN1BitString parse(byte[] bytes) {
        return (ASN1BitString) ASN1.parse(bytes);
    }

    /**
     * Create a BIT STRING element.
     * The unused bits byte (0x00) is automatically prepended to the raw value.
     *
     * @param bitBytes raw bit data (without unused bits prefix)
     * @return ASN1BitString instance
     */
    public static ASN1BitString create(byte[] bitBytes) {
        byte[] value = new byte[1 + bitBytes.length];
        value[0] = 0x00; // unused bits
        System.arraycopy(bitBytes, 0, value, 1, bitBytes.length);
        return new ASN1BitString(value);
    }

    /**
     * Returns the actual bit data, stripping the unused bits prefix byte
     * and clearing the unused trailing bits.
     *
     * @return the bit data without the unused bits metadata
     */
    public byte[] getContent() {
        byte[] rawValue = getValue();
        if (rawValue.length == 0) {
            return new byte[0];
        }
        int unusedBits = UnsignedNumberUtil.getUnsignedByte(rawValue[0]);
        byte[] content = Arrays.copyOfRange(rawValue, 1, rawValue.length);
        content[content.length - 1] = (byte) ((content[content.length - 1] >> unusedBits) << unusedBits);
        return content;
    }
}
