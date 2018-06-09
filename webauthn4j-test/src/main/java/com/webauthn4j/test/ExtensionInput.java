package com.webauthn4j.test;

public interface ExtensionInput<T> {

    String getIdentifier();

    T getValue();

}
