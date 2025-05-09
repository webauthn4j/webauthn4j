package com.webauthn4j.credential;

import com.webauthn4j.authenticator.CoreAuthenticator;
import org.jetbrains.annotations.Nullable;

/**
 * Core interface that represents FIDO CTAP2 credential record (Passkey credential record without ClientData).
 */
public interface CoreCredentialRecord extends CoreAuthenticator {

    /**
     * Gets the user verification (UV) initialization status of this credential.
     *
     * @return `true` if user verification is initialized, `false` if user verification is not initialized,
     *         `null` if no data is available (for backward compatibility).
     */
    @Nullable Boolean isUvInitialized() ;


    /**
     * Sets the user verification (UV) initialization status of this credential.
     *
     * @param value `true` to set the credential as user verification initialized, `false` otherwise.
     */
    void setUvInitialized(boolean value);

    /**
     * Gets the backup eligibility status of this credential.
     *
     * @return `true` if this credential is backup eligible, `false` if it is NOT backup eligible,
     *         `null` if no data is available (for backward compatibility).
     */
    @Nullable Boolean isBackupEligible();

    /**
     * Sets the backup eligibility status of this credential.
     *
     * @param value `true` to mark the credential as backup eligible, `false` otherwise.
     */
    void setBackupEligible(boolean value);

    /**
     * Gets the backup state of this credential.
     *
     * @return `true` if this credential is backed up, `false` if it is NOT backed up,
     *         `null` if no data is available (for backward compatibility).
     */
    @Nullable Boolean isBackedUp();

    /**
     * Sets the backup state of this credential.
     *
     * @param value `true` to mark the credential as backed up, `false` otherwise.
     */
    void setBackedUp(boolean value);

}
