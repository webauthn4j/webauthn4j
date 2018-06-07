package com.webauthn4j.test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.extension.ExtensionOutput;

import java.util.Objects;

public abstract class AbstractExtensionInput<T> implements ExtensionInput<T> {

    private T value;

    @JsonCreator
    public AbstractExtensionInput(T value) {
        this.value = value;
    }

    @JsonValue
    public T getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractExtensionInput that = (AbstractExtensionInput) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
