package com.webauthn4j.verifier.internal.asn1;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.nio.ByteBuffer;
import java.util.Objects;

public class ASN1Tag {

    // Tag and data types
    public static final int ANY = 0x00;
    public static final int BOOLEAN = 0x01;
    public static final int INTEGER = 0x02;
    public static final int BIT_STRING = 0x03;
    public static final int OCTET_STRING = 0x04;
    public static final int NULL = 0x05;
    public static final int OBJECT_IDENTIFIER = 0x06;
    public static final int REAL = 0x09;
    public static final int ENUMERATED = 0x0A;
    public static final int UTF8_STRING = 0x0C;

    public static final int SEQUENCE = 0x10;
    public static final int SET = 0x11;

    public static final int NUMERIC_STRING = 0x12;
    public static final int PRINTABLE_STRING = 0x13;
    public static final int VIDEOTEX_STRING = 0x15;
    public static final int IA5_STRING = 0x16;
    public static final int UTC_TIME = 0x17;
    public static final int GRAPHIC_STRING = 0x19;
    public static final int ISO646_STRING = 0x1A;
    public static final int GENERAL_STRING = 0x1B;

    public static final int UNIVERSAL_STRING = 0x1C;
    public static final int BMP_STRING = 0x1E;


    public static final int CONTEXT_SPECIFIC = 0x80;

    private static final int CLASS_MASK = 0b11000000;
    private static final int CONSTRUCTED_MASK = 0b00100000;
    private static final int NUMBER_MASK = 0b00011111;
    private static final int LEADING_BIT_MASK = 0b10000000;

    public static ASN1Tag parse(ByteBuffer byteBuffer) {
        byte byteValue = byteBuffer.get();
        ASN1TagClass tagClass = ASN1TagClass.from(byteValue);
        int unsignedByteValue = UnsignedNumberUtil.getUnsignedByte(byteValue);

        boolean tagConstructed = (unsignedByteValue & CONSTRUCTED_MASK) > 0;
        int tagNumber = 0;
        if ((unsignedByteValue & NUMBER_MASK) != NUMBER_MASK) {
            // non-extended (8.1.2.3)
            tagNumber = unsignedByteValue & NUMBER_MASK;
        } else {
            // extended (8.1.2.4)
            while (true) {
                int octet = UnsignedNumberUtil.getUnsignedByte(byteBuffer.get());
                tagNumber = tagNumber * 128 + (octet & ~LEADING_BIT_MASK);
                if ((octet & LEADING_BIT_MASK) == 0) break;
            }
        }

        return new ASN1Tag(tagClass, tagConstructed, tagNumber);
    }

    private final ASN1TagClass tagClass;
    private final boolean constructed;
    private final int number;

    ASN1Tag(ASN1TagClass tagClass, boolean constructed, int number) {
        this.tagClass = tagClass;
        this.constructed = constructed;
        this.number = number;
    }

    public ASN1TagClass getTagClass() {
        return tagClass;
    }

    public boolean isConstructed() {
        return constructed;
    }

    public int getNumber() {
        return number;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ASN1Tag asn1Tag = (ASN1Tag) o;
        return constructed == asn1Tag.constructed && number == asn1Tag.number && tagClass == asn1Tag.tagClass;
    }

    @Override
    public int hashCode() {
        return Objects.hash(tagClass, constructed, number);
    }

    public enum ASN1TagClass {
        UNIVERSAL((byte) 0b00000000),
        APPLICATION((byte) 0b01000000),
        CONTEXT_SPECIFIC((byte) 0b10000000),
        PRIVATE((byte) 0b11000000);

        private final byte value;

        ASN1TagClass(byte value) {
            this.value = value;
        }

        public byte getValue() {
            return value;
        }

        public static ASN1TagClass from(byte value) {
            byte classBits = (byte)(value & CLASS_MASK);
            for (ASN1TagClass tagClass : ASN1TagClass.values()) {
                if (classBits == tagClass.getValue()) {
                    return tagClass;
                }
            }
            throw new IllegalArgumentException("Invalid tag class value: " + Integer.toBinaryString(value));
        }
    }
}
