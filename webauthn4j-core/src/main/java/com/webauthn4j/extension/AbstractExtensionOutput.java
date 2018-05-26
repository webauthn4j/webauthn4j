package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Objects;

public abstract class AbstractExtensionOutput<T> implements ExtensionOutput {

    private T value;

    @JsonCreator
    public AbstractExtensionOutput(T value) {
        this.value = value;
    }

    @JsonValue
    public T getValue() {
        return value;
    }

    @Override
    public void validate() {
        //nop
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractExtensionOutput that = (AbstractExtensionOutput) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
