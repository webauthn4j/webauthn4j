package com.webauthn4j.credential;

import com.webauthn4j.authenticator.CoreAuthenticator;
import org.jetbrains.annotations.Nullable;

/**
 * Core interface that represents FIDO CTAP2 credential record (Passkey credential record without ClientData)
 */
public interface CoreCredentialRecord extends CoreAuthenticator {

    /**
     *
     * @return `true` if UV is initialized. `false` if UV is not initialized. `null` if no data is available(for backward compatibility).
     */
    @Nullable Boolean isUvInitialized() ;


    void setUvInitialized(boolean value);

    /**
     *
     * @return `true` if it is backup eligible. `false` if it is NOT backup eligible. `null` if no data is available(for backward compatibility).
     */
    @Nullable Boolean isBackupEligible();

    void setBackupEligible(boolean value);

    /**
     *
     * @return `true` if it is backed up. `false` if it is NOT backed up. `null` if no data is available(for backward compatibility).
     */
    @Nullable Boolean isBackedUp();

    void setBackedUp(boolean value);

}
