package com.webauthn4j.extension.authneticator;

import com.webauthn4j.extension.AbstractExtensionOutput;

public abstract class AbstractAuthenticatorExtensionOutput<T> extends AbstractExtensionOutput<T> implements AuthenticatorExtensionOutput{

    public AbstractAuthenticatorExtensionOutput(T value) {
        super(value);
    }
}
