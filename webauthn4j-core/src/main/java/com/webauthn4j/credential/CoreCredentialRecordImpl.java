package com.webauthn4j.credential;

import com.webauthn4j.authenticator.CoreAuthenticatorImpl;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.*;

/**
 * Implementation of the {@link CoreCredentialRecord} interface representing a FIDO CTAP2 credential record.
 * This class provides core functionality for managing credential data, user verification status,
 * backup eligibility, and backup state.
 */
public class CoreCredentialRecordImpl extends CoreAuthenticatorImpl implements CoreCredentialRecord{

    private Boolean uvInitialized;
    private Boolean backupEligible;
    private Boolean backupState;

    /**
     * Constructs a new CoreCredentialRecordImpl from an attestation object.
     * This constructor extracts necessary information from the attestation object
     * including attested credential data, attestation statement, sign count, and flags.
     *
     * @param attestationObject the attestation object containing credential data and flags
     */
    public CoreCredentialRecordImpl(@NotNull AttestationObject attestationObject){

        //As AttestationObject always have AttestedCredentialData, this won't be an issue
        //noinspection DataFlowIssue
        super(attestationObject.getAuthenticatorData().getAttestedCredentialData(),
                attestationObject.getAttestationStatement(),
                attestationObject.getAuthenticatorData().getSignCount(),
                attestationObject.getAuthenticatorData().getExtensions());
        this.uvInitialized = (attestationObject.getAuthenticatorData().getFlags() & BIT_UV) != 0;
        this.backupEligible = (attestationObject.getAuthenticatorData().getFlags() & BIT_BE) != 0;
        this.backupState = (attestationObject.getAuthenticatorData().getFlags() & BIT_BS) != 0;
    }

    /**
     * Constructs a new CoreCredentialRecordImpl with the specified parameters.
     * This constructor allows explicit setting of all credential record properties.
     *
     * @param attestationStatement    the attestation statement, may be null
     * @param uvInitialized           the user verification initialization status, may be null for backward compatibility
     * @param backupEligible          the backup eligibility status, may be null for backward compatibility
     * @param backupState             the backup state, may be null for backward compatibility
     * @param counter                 the signature counter value
     * @param attestedCredentialData  the attested credential data, must not be null
     * @param authenticatorExtensions the authenticator extensions, may be null
     */
    public CoreCredentialRecordImpl(
            @Nullable AttestationStatement attestationStatement,
            @Nullable Boolean uvInitialized,
            @Nullable Boolean backupEligible,
            @Nullable Boolean backupState,
            long counter,
            @NotNull AttestedCredentialData attestedCredentialData,
            @Nullable AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions) {
        super(attestedCredentialData, attestationStatement, counter, authenticatorExtensions);
        this.uvInitialized = uvInitialized;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean isUvInitialized() {
        return this.uvInitialized;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setUvInitialized(boolean value) {
        this.uvInitialized = value;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean isBackupEligible() {
        return this.backupEligible;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setBackupEligible(boolean value) {
        this.backupEligible = value;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean isBackedUp() {
        return this.backupState;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setBackedUp(boolean value) {
        this.backupState = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CoreCredentialRecordImpl that = (CoreCredentialRecordImpl) o;
        return Objects.equals(uvInitialized, that.uvInitialized) && Objects.equals(backupEligible, that.backupEligible) && Objects.equals(backupState, that.backupState);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), uvInitialized, backupEligible, backupState);
    }
}
