package com.webauthn4j.attestation.authenticator;

import java.io.Serializable;
import java.util.Objects;

public abstract class AbstractSignatureAlgorithm implements Serializable {

    private int value;
    private String name;

    public AbstractSignatureAlgorithm(int value, String name){
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractSignatureAlgorithm that = (AbstractSignatureAlgorithm) o;
        return value == that.value &&
                Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {

        return Objects.hash(value, name);
    }
}
