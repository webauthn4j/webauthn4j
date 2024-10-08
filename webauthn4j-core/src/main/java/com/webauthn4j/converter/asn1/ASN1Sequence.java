package com.webauthn4j.converter.asn1;

import java.util.List;

public class ASN1Sequence extends ASN1 implements ASN1Structure{

    private final List<ASN1> value;

    public ASN1Sequence(ASN1Tag tag, ASN1Length length, List<ASN1> value) {
        super(tag, length);
        this.value = value;
    }

    public List<ASN1> getValue() {
        return value;
    }



}
