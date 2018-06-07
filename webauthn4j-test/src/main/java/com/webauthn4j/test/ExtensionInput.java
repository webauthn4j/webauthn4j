package com.webauthn4j.test;

import com.webauthn4j.extension.ExtensionIdentifier;

public interface ExtensionInput<T> {

    ExtensionIdentifier getIdentifier();

    T getValue();

}
