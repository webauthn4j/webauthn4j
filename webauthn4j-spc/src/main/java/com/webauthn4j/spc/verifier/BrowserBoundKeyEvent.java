package com.webauthn4j.spc.verifier;

import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import org.jetbrains.annotations.NotNull;

public abstract class BrowserBoundKeyEvent {

    private final AuthenticationObject authenticationObject;

    protected BrowserBoundKeyEvent(@NotNull AuthenticationObject authenticationObject) {
        AssertUtil.notNull(authenticationObject, "authenticationObject must not be null");
        this.authenticationObject = authenticationObject;
    }

    public @NotNull AuthenticationObject getAuthenticationObject() {
        return authenticationObject;
    }
}
