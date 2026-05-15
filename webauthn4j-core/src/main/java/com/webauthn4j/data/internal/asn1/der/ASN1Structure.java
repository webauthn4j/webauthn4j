package com.webauthn4j.data.internal.asn1.der;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import java.util.List;

/**
 * Base class for DER-encoded ASN.1 constructed elements (SEQUENCE, SET, etc.).
 * <p>
 * For SEQUENCE, use {@link ASN1Sequence}.
 * For unknown or context-specific constructed types, this class is used directly.
 * <p>
 * Use {@link ASN1#parse(byte[])} to parse DER-encoded data.
 */
public class ASN1Structure extends ASN1 implements Iterable<ASN1> {

    /**
     * Compute the total value length from children's encoded sizes.
     */
    private static int computeValueLength(List<ASN1> children) {
        return children.stream().mapToInt(child ->
                child.getTag().toBytes().length + child.getLength().toBytes().length + child.getLength().getValueLength()
        ).sum();
    }

    private final List<ASN1> value;

    /**
     * Constructor for parsed data — preserves the original T, L.
     */
    ASN1Structure(ASN1Tag tag, ASN1Length length, List<ASN1> value) {
        super(tag, length);
        this.value = value;
    }

    /**
     * Constructor for programmatic construction — L is computed from children.
     */
    ASN1Structure(ASN1Tag tag, List<ASN1> value) {
        super(tag, computeValueLength(value));
        this.value = value;
    }

    public ASN1 get(int index) {
        return value.get(index);
    }

    public int size() {
        return value.size();
    }

    @Override
    public @NotNull Iterator<ASN1> iterator() {
        return this.value.iterator();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ASN1Structure that = (ASN1Structure) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    protected byte[] getValue() {
        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();
        for (ASN1 child : value) {
            byte[] childBytes = child.toBytes();
            contentStream.write(childBytes, 0, childBytes.length);
        }
        return contentStream.toByteArray();
    }
}
