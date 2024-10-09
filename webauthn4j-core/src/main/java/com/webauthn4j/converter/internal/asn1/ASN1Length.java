package com.webauthn4j.converter.internal.asn1;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.nio.ByteBuffer;
import java.util.Objects;


public class ASN1Length {

    private static final int LEADING_BIT_MASK = 0b10000000;

    static ASN1Length parse(ByteBuffer byteBuffer) {
        byte firstByte = byteBuffer.get();
        boolean longForm = (firstByte & LEADING_BIT_MASK) != 0;
        int valueLength = 0;
        if (!longForm) {
            // definite short form (8.1.3.4)
            valueLength = firstByte & ~LEADING_BIT_MASK;
        } else {
            // either definite long form (8.1.3.5) or indefinite form (8.1.3.6)
            int octets = UnsignedNumberUtil.getUnsignedByte((byte)(firstByte & ~LEADING_BIT_MASK));
            for (int i = 0; i < octets; i++) {
                valueLength = valueLength * 256 + UnsignedNumberUtil.getUnsignedByte(byteBuffer.get());
            }
        }

        return new ASN1Length(longForm && valueLength == 0, valueLength);
    }

    private final boolean indefinite;
    private final int valueLength;

    private ASN1Length(boolean indefinite, int valueLength) {
        this.indefinite = indefinite;
        this.valueLength = valueLength;
    }

    public boolean isIndefinite() {
        return indefinite;
    }

    public int getValueLength() {
        return valueLength;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ASN1Length asn1Length = (ASN1Length) o;
        return indefinite == asn1Length.indefinite && valueLength == asn1Length.valueLength;
    }

    @Override
    public int hashCode() {
        return Objects.hash(indefinite, valueLength);
    }
}
