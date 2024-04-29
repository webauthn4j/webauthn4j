package com.webauthn4j.credential;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.client.CollectedClientData;
import org.jetbrains.annotations.Nullable;

/**
 * Core interface that represents Passkey(WebAuthn) credential record
 */
public interface CredentialRecord extends CoreCredentialRecord, Authenticator {

    /**
     *
     * @return client data. `null` if no data is available(for backward compatibility).
     */
    @Nullable CollectedClientData getClientData();

}
