package com.webauthn4j.extension.client;

import com.webauthn4j.extension.AbstractExtensionOutput;

public abstract class AbstractClientExtensionOutput<T> extends AbstractExtensionOutput<T> implements ClientExtensionOutput {

    public AbstractClientExtensionOutput(T value) {
        super(value);
    }
}
