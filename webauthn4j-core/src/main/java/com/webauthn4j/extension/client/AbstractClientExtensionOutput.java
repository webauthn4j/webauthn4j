package com.webauthn4j.extension.client;

import com.webauthn4j.extension.AbstractExtensionOutput;

public abstract class AbstractClientExtensionOutput<T> extends AbstractExtensionOutput<T> implements ClientExtensionOutput<T> {

    public AbstractClientExtensionOutput(T value) {
        super(value);
    }
}
