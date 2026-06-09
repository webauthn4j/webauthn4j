package com.webauthn4j.spc.verifier;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import org.jetbrains.annotations.NotNull;

public class UnknownBrowserBoundKeyEvent extends BrowserBoundKeyEvent {

    private final COSEKey presentedKey;

    public UnknownBrowserBoundKeyEvent(
            @NotNull AuthenticationObject authenticationObject,
            @NotNull COSEKey presentedKey) {
        super(authenticationObject);
        AssertUtil.notNull(presentedKey, "presentedKey must not be null");
        this.presentedKey = presentedKey;
    }

    public @NotNull COSEKey getPresentedKey() {
        return presentedKey;
    }
}
