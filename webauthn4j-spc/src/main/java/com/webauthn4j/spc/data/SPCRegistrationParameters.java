package com.webauthn4j.spc.data;

import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.server.ServerProperty;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class SPCRegistrationParameters extends RegistrationParameters {

    public SPCRegistrationParameters(
            @NotNull ServerProperty serverProperty,
            @NotNull List<com.webauthn4j.data.PublicKeyCredentialParameters> pubKeyCredParams,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        super(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);
    }

    public SPCRegistrationParameters(
            @NotNull ServerProperty serverProperty,
            @NotNull List<com.webauthn4j.data.PublicKeyCredentialParameters> pubKeyCredParams) {
        super(serverProperty, pubKeyCredParams, true, true);
    }
}
