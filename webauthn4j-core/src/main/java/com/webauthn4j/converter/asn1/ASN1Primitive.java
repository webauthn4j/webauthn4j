package com.webauthn4j.converter.asn1;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class ASN1Primitive extends ASN1{

    private byte[] value;

    public static byte[] parseValue(ByteBuffer byteBuffer, ASN1Tag tag, ASN1Length length) {
        byte[] buffer = new byte[length.getValueLength()];
        byteBuffer.get(buffer);
        return buffer;
    }


    ASN1Primitive(ASN1Tag tag, ASN1Length length, byte[] value) {
        super(tag, length);
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }

    public BigInteger asBigInteger() {
        return new BigInteger(value);
    }


}
