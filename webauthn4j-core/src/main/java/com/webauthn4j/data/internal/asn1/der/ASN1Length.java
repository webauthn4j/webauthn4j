package com.webauthn4j.data.internal.asn1.der;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.nio.ByteBuffer;

/**
 * DER length field.
 * DER uses definite-length encoding only; indefinite length is not supported.
 */
class ASN1Length {

    private static final int LEADING_BIT_MASK = 0b10000000;

    static ASN1Length parse(ByteBuffer byteBuffer) {
        byte firstByte = byteBuffer.get();
        boolean longForm = (firstByte & LEADING_BIT_MASK) != 0;
        if (!longForm) {
            // definite short form (8.1.3.4)
            int valueLength = firstByte & ~LEADING_BIT_MASK;
            return new ASN1Length(valueLength);
        }
        else {
            int octets = UnsignedNumberUtil.getUnsignedByte((byte) (firstByte & ~LEADING_BIT_MASK));
            if (octets == 0) {
                throw new IllegalArgumentException("Indefinite length is not allowed in DER");
            }
            // definite long form (8.1.3.5)
            int valueLength = 0;
            for (int i = 0; i < octets; i++) {
                valueLength = valueLength * 256 + UnsignedNumberUtil.getUnsignedByte(byteBuffer.get());
            }
            return new ASN1Length(valueLength);
        }
    }

    private final int valueLength;

    ASN1Length(int valueLength) {
        this.valueLength = valueLength;
    }

    public int getValueLength() {
        return valueLength;
    }

    /**
     * Encode this length to DER byte array.
     *
     * @return DER-encoded length bytes
     */
    public byte[] toBytes() {
        if (valueLength < 128) {
            return new byte[]{(byte) valueLength};
        }
        else if (valueLength < 256) {
            return new byte[]{(byte) 0x81, (byte) valueLength};
        }
        else if (valueLength < 65536) {
            return new byte[]{(byte) 0x82, (byte) (valueLength >> 8), (byte) (valueLength & 0xFF)};
        }
        else {
            return new byte[]{(byte) 0x83, (byte) (valueLength >> 16), (byte) ((valueLength >> 8) & 0xFF), (byte) (valueLength & 0xFF)};
        }
    }
}
