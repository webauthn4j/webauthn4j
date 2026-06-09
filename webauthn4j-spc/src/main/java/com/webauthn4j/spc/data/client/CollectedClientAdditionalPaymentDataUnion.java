package com.webauthn4j.spc.data.client;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import org.jetbrains.annotations.Nullable;

public interface CollectedClientAdditionalPaymentDataUnion {

    @Nullable COSEKey getBrowserBoundPublicKey();
}
