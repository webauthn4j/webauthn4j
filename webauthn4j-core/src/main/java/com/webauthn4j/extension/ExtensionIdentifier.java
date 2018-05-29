package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Objects;

public class ExtensionIdentifier {

    private String value;

    @SuppressWarnings("WeakerAccess")
    @JsonCreator
    public ExtensionIdentifier(String value){
        this.value = value;
    }

    @JsonValue
    public String getValue(){
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtensionIdentifier that = (ExtensionIdentifier) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {

        return Objects.hash(value);
    }
}
