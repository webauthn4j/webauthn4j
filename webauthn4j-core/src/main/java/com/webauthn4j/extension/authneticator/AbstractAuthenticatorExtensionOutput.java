package com.webauthn4j.extension.authneticator;

import com.webauthn4j.extension.AbstractExtensionOutput;

public abstract class AbstractAuthenticatorExtensionOutput<T> extends AbstractExtensionOutput<T> implements AuthenticatorExtensionOutput<T>{

    public AbstractAuthenticatorExtensionOutput(T value) {
        super(value);
    }
}
