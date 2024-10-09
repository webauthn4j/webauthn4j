package com.webauthn4j.verifier.internal.asn1;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.List;

public class ASN1Sequence extends ASN1 implements ASN1Structure{

    public static ASN1Sequence parse(byte[] bytes) {
        return parse(ByteBuffer.wrap(bytes));
    }

    public static ASN1Sequence parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, length);
            return new ASN1Sequence(tag, length, value); //TODO: non-sequence structure
        }
        else {
            throw new IllegalArgumentException("primitive data is provided");
        }
    }

    private final List<ASN1> value;

    public ASN1Sequence(ASN1Tag tag, ASN1Length length, List<ASN1> value) {
        super(tag, length);
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
}
