package com.webauthn4j.converter.asn1;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

public class ASN1 {

    public static ASN1 parseASN1(byte[] bytes) {
        return parseASN1(ByteBuffer.wrap(bytes));
    }

    public static ASN1 parseASN1(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, tag, length);
            return new ASN1Sequence(tag, length, value); //TODO: ASN1Set
        }
        else {
            byte[] value = ASN1Primitive.parseValue(byteBuffer, tag, length);
            return new ASN1Primitive(tag, length, value);
        }
    }

    private static final int CLASS_MASK = 0b11000000;
    private static final int CONSTRUCTED_MASK = 0b00100000;
    private static final int NUMBER_MASK = 0b00011111;
    private static final int LEADING_BIT_MASK = 0b10000000;


    private final ASN1Tag tag;
    private final ASN1Length length;

    ASN1(ASN1Tag tag, ASN1Length length) {
        this.tag = tag;
        this.length = length;
    }

//    public byte[] binary(int index) {
//        return (byte[]) getValue().get(index);
//    }
//
//    public int integer(int index) {
//        byte[] bytes = binary(index);
//        if (bytes.length > 4) {
//            throw new IllegalArgumentException("integer too long");
//        }
//        int result = 0;
//        for (byte b : bytes) {
//            result = (result << 8) | (b & 0xFF);
//        }
//        return result;
//    }
//
//    public String oid(int index) {
//        byte[] bytes = object(index, OBJECT_IDENTIFIER).binary(0);
//
//        StringBuilder oid = new StringBuilder();
//
//        for (int i = 0; i < bytes.length; i++) {
//            int uint8 = Byte.toUnsignedInt(bytes[i]);
//
//            if (i == 0) {
//                int b = uint8 % 40;
//                int a = (uint8 - b) / 40;
//                oid
//                        .append(a)
//                        .append('.')
//                        .append(b);
//            } else {
//                if (uint8 < 128) {
//                    oid
//                            .append('.')
//                            .append(uint8);
//                } else {
//                    oid
//                            .append('.')
//                            .append(((uint8 - 128) * 128) + Byte.toUnsignedInt(bytes[i + 1]));
//                    i++;
//                }
//            }
//        }
//
//        return oid.toString();
//    }
//
//
//    public ASN1 object(int index) {
//        return (ASN1) getValue().get(index);
//    }
//
//    public ASN1 object(int index, int type) {
//        ASN1 object = (ASN1) getValue().get(index);
//        if (!object.is(type)) {
//            throw new ClassCastException("Object at index(" + index + ") is not of type: " + type);
//        }
//        return object;
//    }
//
//
//    public int length() {
//        return getValue().size();
//    }

    public ASN1Tag getTag() {
        return tag;
    }

    public ASN1Length getLength() {
        return length;
    }

    public enum ASN1TagClass {
        UNIVERSAL((byte)0b00000000),
        APPLICATION((byte)0b01000000),
        CONTEXT_SPECIFIC((byte)0b10000000),
        PRIVATE((byte)0b11000000);

        private final byte value;

        ASN1TagClass(byte value){
            this.value = value;
        }

        public byte getValue() {
            return value;
        }

        public static ASN1TagClass from(byte value) {
            for (ASN1TagClass tagClass : ASN1TagClass.values()) {
                if (((byte)(value & CLASS_MASK)) == tagClass.getValue()) {
                    return tagClass;
                }
            }
            throw new IllegalArgumentException("Invalid tag class value: "+ Integer.toBinaryString(value));
        }
    }

    public static class ASN1Tag {

        // Tag and data types
        public final static int ANY = 0x00;
        public final static int BOOLEAN = 0x01;
        public final static int INTEGER = 0x02;
        public final static int BIT_STRING = 0x03;
        public final static int OCTET_STRING = 0x04;
        public final static int NULL = 0x05;
        public final static int OBJECT_IDENTIFIER = 0x06;
        public final static int REAL = 0x09;
        public final static int ENUMERATED = 0x0A;
        public final static int UTF8_STRING = 0x0C;

        public final static int SEQUENCE = 0x10;
        public final static int SET = 0x11;

        public final static int NUMERIC_STRING = 0x12;
        public final static int PRINTABLE_STRING = 0x13;
        public final static int VIDEOTEX_STRING = 0x15;
        public final static int IA5_STRING = 0x16;
        public final static int UTC_TIME = 0x17;
        public final static int GRAPHIC_STRING = 0x19;
        public final static int ISO646_STRING = 0x1A;
        public final static int GENERAL_STRING = 0x1B;

        public final static int UNIVERSAL_STRING = 0x1C;
        public final static int BMP_STRING = 0x1E;


        public final static int CONSTRUCTED = 0x20;
        public final static int CONTEXT_SPECIFIC = 0x80;

        private static ASN1Tag parse(ByteBuffer byteBuffer) {
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
        private ASN1Tag(ASN1TagClass tagClass, boolean constructed, int number) {
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
    }

    public static class ASN1Length {

        private static ASN1Length parse(ByteBuffer byteBuffer) {
            int firstByte = byteBuffer.get();
            boolean longForm = (firstByte & LEADING_BIT_MASK) != 0;
            int valueLength = 0;
            if (!longForm) {
                // definite short form (8.1.3.4)
                valueLength = firstByte & ~LEADING_BIT_MASK;
            } else {
                // either definite long form (8.1.3.5) or indefinite form (8.1.3.6)
                int lengthOctets = firstByte & ~LEADING_BIT_MASK;
                for (int i = 0; i < lengthOctets; i++) {
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
}
