package com.webauthn4j.converter.internal.asn1;


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
            ASN1 newObj = ASN1.parse(byteBuffer);
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

}
