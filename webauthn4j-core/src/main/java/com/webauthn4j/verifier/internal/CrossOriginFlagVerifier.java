package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.verifier.exception.CrossOriginException;

import java.util.Objects;

public class CrossOriginFlagVerifier {

    private CrossOriginFlagVerifier(){}

    public static void verify(CollectedClientData collectedClientData, boolean crossOriginAllowed) {
        if (!crossOriginAllowed && Objects.equals(true, collectedClientData.getCrossOrigin())) {
            throw new CrossOriginException("Cross-origin request is prohibited. Relax AuthenticationDataVerifier config if necessary.");
        }
    }
}
