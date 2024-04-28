package com.webauthn4j.credential;

import com.webauthn4j.authenticator.CoreAuthenticatorImpl;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.*;

public class CoreCredentialRecordImpl extends CoreAuthenticatorImpl implements CoreCredentialRecord{

    private Boolean uvInitialized;
    private Boolean backupEligible;
    private Boolean backupState;

    public CoreCredentialRecordImpl(@NonNull AttestationObject attestationObject){

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

    public CoreCredentialRecordImpl(
            @Nullable AttestationStatement attestationStatement,
            @Nullable Boolean uvInitialized,
            @Nullable Boolean backupEligible,
            @Nullable Boolean backupState,
            long counter,
            @NonNull AttestedCredentialData attestedCredentialData,
            @Nullable AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions) {
        super(attestedCredentialData, attestationStatement, counter, authenticatorExtensions);
        this.uvInitialized = uvInitialized;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
    }

    @Override
    public Boolean isUvInitialized() {
        return this.uvInitialized;
    }

    @Override
    public void setUvInitialized(boolean value) {
        this.uvInitialized = value;
    }

    @Override
    public Boolean isBackupEligible() {
        return this.backupEligible;
    }

    @Override
    public void setBackupEligible(boolean value) {
        this.backupEligible = value;
    }

    @Override
    public Boolean isBackedUp() {
        return this.backupState;
    }

    @Override
    public void setBackedUp(boolean value) {
        this.backupState = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CoreCredentialRecordImpl that = (CoreCredentialRecordImpl) o;
        return Objects.equals(uvInitialized, that.uvInitialized) && Objects.equals(backupEligible, that.backupEligible) && Objects.equals(backupState, that.backupState);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), uvInitialized, backupEligible, backupState);
    }
}
