package com.webauthn4j.test.client;

import com.webauthn4j.test.AbstractExtensionInput;

public abstract class AbstractClientExtensionInput<T> extends AbstractExtensionInput<T> implements ClientExtensionInput<T> {

    public AbstractClientExtensionInput(T value) {
        super(value);
    }
}
