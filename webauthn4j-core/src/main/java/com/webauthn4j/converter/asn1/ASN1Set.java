package com.webauthn4j.converter.asn1;

import java.util.Set;

public class ASN1Set extends ASN1 implements ASN1Structure{

    private final Set<Object> value;

    ASN1Set(ASN1Tag tag, ASN1Length length, Set<Object> value) {
        super(tag, length);
        this.value = value;
    }

    public Set<Object> getValue() {
        return value;
    }
}
