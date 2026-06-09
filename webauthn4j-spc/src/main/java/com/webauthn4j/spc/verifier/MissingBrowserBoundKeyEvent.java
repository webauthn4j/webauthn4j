package com.webauthn4j.spc.verifier;

import com.webauthn4j.verifier.AuthenticationObject;
import org.jetbrains.annotations.NotNull;

public class MissingBrowserBoundKeyEvent extends BrowserBoundKeyEvent {

    public MissingBrowserBoundKeyEvent(@NotNull AuthenticationObject authenticationObject) {
        super(authenticationObject);
    }
}
