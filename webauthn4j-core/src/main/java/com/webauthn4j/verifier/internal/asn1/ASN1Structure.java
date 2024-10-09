package com.webauthn4j.verifier.internal.asn1;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ASN1Structure extends ASN1 implements Iterable<ASN1>{

    public static ASN1Structure parse(byte[] bytes) {
        return parse(ByteBuffer.wrap(bytes));
    }

    public static ASN1Structure parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, length);
            return new ASN1Structure(tag, length, value);
        }
        else {
            throw new IllegalArgumentException("primitive data is provided");
        }
    }

    static List<ASN1> parseValue(ByteBuffer byteBuffer, ASN1Length length) {
        List<ASN1> res = new ArrayList<>();
        int valueLength = length.getValueLength();
        int readLength = 0;
        while (readLength < valueLength) {
            int beforePos = byteBuffer.position();
            ASN1 newObj = parseChild(byteBuffer);
            int afterPos = byteBuffer.position();
            int newObjLength = afterPos - beforePos;
            readLength += newObjLength;

            if (newObj.getTag().getTagClass() == ASN1Tag.ASN1TagClass.UNIVERSAL &&
                    !newObj.getTag().isConstructed() &&
                    newObj.getTag().getNumber() == 0 &&
                    newObj.getLength().getValueLength() == 0) {
                break; // end-of-contents contents (8.1.5)
            }

            res.add(newObj);
        }

        return res;
    }

    static ASN1 parseChild(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, length);
            return new ASN1Structure(tag, length, value);
        }
        else {
            byte[] value = ASN1Primitive.parseValue(byteBuffer, length);
            return new ASN1Primitive(tag, length, value);
        }
    }


    private final List<ASN1> value;

    public ASN1Structure(ASN1Tag tag, ASN1Length length, List<ASN1> value) {
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
