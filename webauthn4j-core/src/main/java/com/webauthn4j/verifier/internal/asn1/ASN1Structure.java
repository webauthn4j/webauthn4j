package com.webauthn4j.verifier.internal.asn1;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public interface ASN1Structure extends Iterable<ASN1> {

    static List<ASN1> parseValue(ByteBuffer byteBuffer, ASN1Length length) {
        List<ASN1> res = new ArrayList<>();
        int valueLength = length.getValueLength();
        int readLength = 0;
        while (readLength < valueLength) {
            int beforePos = byteBuffer.position();
            ASN1 newObj = parse(byteBuffer);
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

    static ASN1 parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, length);
            return new ASN1Sequence(tag, length, value); //TODO: non-sequence structure
        }
        else {
            byte[] value = ASN1Primitive.parseValue(byteBuffer, length);
            return new ASN1Primitive(tag, length, value);
        }
    }

}
