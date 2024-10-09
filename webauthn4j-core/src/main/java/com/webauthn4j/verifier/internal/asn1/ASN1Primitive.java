package com.webauthn4j.verifier.internal.asn1;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ASN1Primitive extends ASN1{

    public static ASN1Primitive parse(byte[] bytes) {
        return parse(ByteBuffer.wrap(bytes));
    }

    public static ASN1Primitive parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            throw new IllegalArgumentException("non primitive data is provided");
        }
        else {
            byte[] value = ASN1Primitive.parseValue(byteBuffer, length);
            return new ASN1Primitive(tag, length, value);
        }
    }

    public static byte[] parseValue(ByteBuffer byteBuffer, ASN1Length length) {
        byte[] buffer = new byte[length.getValueLength()];
        byteBuffer.get(buffer);
        return buffer;
    }

    private final byte[] value;

    ASN1Primitive(ASN1Tag tag, ASN1Length length, byte[] value) {
        super(tag, length);
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }

    public String getValueAsUtf8String() {
        return new String(value, StandardCharsets.UTF_8);
    }

    public byte[] getValueAsBitString() {
        if(this.value.length == 0){
            return new byte[0];
        }
        int unusedBits = UnsignedNumberUtil.getUnsignedByte(value[0]);
        byte[] cloned = Arrays.copyOfRange(this.value, 1, this.value.length);
        cloned[cloned.length -1] = (byte)((cloned[cloned.length - 1] >> unusedBits) << unusedBits);

        return cloned;
    }

    public BigInteger getValueAsBigInteger() {
        return new BigInteger(value);
    }

    public ASN1Primitive getValueAsASN1Primitive(){
        return ASN1Primitive.parse(getValue());
    }

    public ASN1Sequence getValueAsASN1Sequence(){
        return ASN1Sequence.parse(getValue());
    }

}
