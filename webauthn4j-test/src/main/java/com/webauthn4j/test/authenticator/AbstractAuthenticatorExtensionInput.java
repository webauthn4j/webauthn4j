package com.webauthn4j.test.authenticator;

import com.webauthn4j.test.AbstractExtensionInput;

public abstract class AbstractAuthenticatorExtensionInput<T> extends AbstractExtensionInput<T> implements AuthenticatorExtensionInput<T> {

    public AbstractAuthenticatorExtensionInput(T value) {
        super(value);
    }
}
