package com.webauthn4j.data.internal.asn1.der;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * DER-encoded ASN.1 SEQUENCE element.
 */
public class ASN1Sequence extends ASN1Structure {

    private static final ASN1Tag TAG = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, true, ASN1Tag.SEQUENCE);

    /**
     * Constructor for parsed data — preserves the original length field.
     */
    ASN1Sequence(ASN1Length length, List<ASN1> children) {
        super(TAG, length, children);
    }

    /**
     * Constructor for programmatic construction.
     */
    ASN1Sequence(List<ASN1> children) {
        super(TAG, children);
    }

    /**
     * Parse DER-encoded data as a SEQUENCE element.
     *
     * @param bytes DER-encoded data
     * @return ASN1Sequence instance
     */
    public static ASN1Sequence parse(byte[] bytes) {
        return (ASN1Sequence) ASN1.parse(bytes);
    }

    /**
     * Create a SEQUENCE element.
     *
     * @param children child ASN.1 elements
     * @return ASN1Sequence instance
     */
    public static ASN1Sequence create(ASN1... children) {
        return create(Arrays.asList(children));
    }

    /**
     * Create a SEQUENCE element.
     *
     * @param children child ASN.1 elements
     * @return ASN1Sequence instance
     */
    public static ASN1Sequence create(List<ASN1> children) {
        return new ASN1Sequence(new ArrayList<>(children));
    }
}
