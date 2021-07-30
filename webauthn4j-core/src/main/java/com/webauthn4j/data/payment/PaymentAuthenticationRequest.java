package com.webauthn4j.data.payment;

import com.webauthn4j.data.AuthenticationRequest;
import org.checkerframework.checker.nullness.qual.Nullable;

public class PaymentAuthenticationRequest extends AuthenticationRequest {
    public PaymentAuthenticationRequest(@Nullable byte[] credentialId, @Nullable byte[] userHandle, @Nullable byte[] authenticatorData, @Nullable byte[] clientDataJSON, @Nullable String clientExtensionsJSON, @Nullable byte[] signature) {
        super(credentialId, userHandle, authenticatorData, clientDataJSON, clientExtensionsJSON, signature);
    }

    public PaymentAuthenticationRequest(@Nullable byte[] credentialId, @Nullable byte[] authenticatorData, @Nullable byte[] clientDataJSON, @Nullable String clientExtensionsJSON, @Nullable byte[] signature) {
        super(credentialId, authenticatorData, clientDataJSON, clientExtensionsJSON, signature);
    }

    public PaymentAuthenticationRequest(@Nullable byte[] credentialId, @Nullable byte[] userHandle, @Nullable byte[] authenticatorData, @Nullable byte[] clientDataJSON, @Nullable byte[] signature) {
        super(credentialId, userHandle, authenticatorData, clientDataJSON, signature);
    }

    public PaymentAuthenticationRequest(@Nullable byte[] credentialId, @Nullable byte[] authenticatorData, @Nullable byte[] clientDataJSON, @Nullable byte[] signature) {
        super(credentialId, authenticatorData, clientDataJSON, signature);
    }
}
