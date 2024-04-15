package com.webauthn4j.credential;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;
import java.util.Set;

public class CredentialRecordImpl extends CoreCredentialRecordImpl implements CredentialRecord{

    private final CollectedClientData clientData;
    private final AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private final Set<AuthenticatorTransport> transports;

    public CredentialRecordImpl(
            @NonNull AttestationObject attestationObject,
            @Nullable CollectedClientData clientData,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports) {
        super(attestationObject);
        this.clientData = clientData;
        this.clientExtensions = clientExtensions;
        this.transports = transports;
    }

    public CredentialRecordImpl(
            @NonNull AttestationStatement attestationStatement,
            @Nullable Boolean uvInitialized,
            @Nullable Boolean backupEligible,
            @Nullable Boolean backupState,
            long counter,
            @NonNull AttestedCredentialData attestedCredentialData,
            @NonNull AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions,
            @Nullable CollectedClientData clientData,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports) {
        super(attestationStatement, uvInitialized, backupEligible, backupState, counter, attestedCredentialData, authenticatorExtensions);
        this.clientData = clientData;
        this.clientExtensions = clientExtensions;
        this.transports = transports;
    }

    @Override
    public @Nullable CollectedClientData getClientData() {
        return clientData;
    }

    @Override
    public @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    @Override
    public @Nullable Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CredentialRecordImpl that = (CredentialRecordImpl) o;
        return Objects.equals(clientData, that.clientData) && Objects.equals(clientExtensions, that.clientExtensions) && Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), clientData, clientExtensions, transports);
    }
}
