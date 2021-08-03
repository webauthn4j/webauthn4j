package com.webauthn4j.data.payment;

import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import org.checkerframework.checker.nullness.qual.Nullable;

public class PaymentAuthenticationData extends AuthenticationData {

    public PaymentAuthenticationData(@Nullable byte[] credentialId,
                                     @Nullable byte[] userHandle,
                                     @Nullable AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
                                     @Nullable byte[] authenticatorDataBytes,
                                     @Nullable CollectedClientPaymentData collectedClientPaymentData,
                                     @Nullable byte[] collectedClientPaymentDataBytes,
                                     @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
                                     @Nullable byte[] signature) {
        super(credentialId, userHandle, authenticatorData, authenticatorDataBytes, collectedClientPaymentData, collectedClientPaymentDataBytes, clientExtensions, signature);
    }

    @Override
    public CollectedClientPaymentData getCollectedClientData() {
        return (CollectedClientPaymentData) super.getCollectedClientData();
    }
}
