package com.webauthn4j.data.internal.asn1.der;

/**
 * DER-encoded ASN.1 OBJECT IDENTIFIER element.
 */
public class ASN1ObjectIdentifier extends ASN1Primitive {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.OBJECT_IDENTIFIER);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1ObjectIdentifier(ASN1Length length, byte[] value) {
        super(TAG, length, value);
    }

    /**
     * Constructor for programmatic construction.
     */
    ASN1ObjectIdentifier(byte[] value) {
        super(TAG, value);
    }

    /**
     * Parse DER-encoded data as an OBJECT IDENTIFIER element.
     *
     * @param bytes DER-encoded data
     * @return ASN1ObjectIdentifier instance
     */
    public static ASN1ObjectIdentifier parse(byte[] bytes) {
        return (ASN1ObjectIdentifier) ASN1.parse(bytes);
    }

    /**
     * Create an OBJECT IDENTIFIER element from encoded OID value bytes.
     *
     * @param oidValue encoded OID value bytes (without tag and length)
     * @return ASN1ObjectIdentifier instance
     */
    public static ASN1ObjectIdentifier create(byte[] oidValue) {
        return new ASN1ObjectIdentifier(oidValue);
    }

    /**
     * Returns the OID in dot notation (e.g. "2.5.4.3").
     *
     * @return dot-notation string
     */
    public String getContent() {
        byte[] value = getValue();
        if (value.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        // First octet encodes two components: first = min(byte/40, 2), second = byte - 40*first
        int firstByte = value[0] & 0xFF;
        int first = Math.min(firstByte / 40, 2);
        int second = firstByte - 40 * first;
        sb.append(first).append('.').append(second);

        // Subsequent components are base-128 encoded
        long component = 0;
        for (int i = 1; i < value.length; i++) {
            int b = value[i] & 0xFF;
            component = (component << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(component);
                component = 0;
            }
        }

        return sb.toString();
    }
}
