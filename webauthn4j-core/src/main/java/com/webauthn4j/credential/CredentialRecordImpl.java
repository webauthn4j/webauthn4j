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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;
import java.util.Set;

/**
 * Implementation of the {@link CredentialRecord} interface representing a WebAuthn (Passkey) credential record.
 * This class extends {@link CoreCredentialRecordImpl} and adds WebAuthn (Passkey) specific capabilities including
 * collected client data, client extensions, and authenticator transport information.
 */
public class CredentialRecordImpl extends CoreCredentialRecordImpl implements CredentialRecord{

    private final CollectedClientData clientData;
    private final AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private final Set<AuthenticatorTransport> transports;

    /**
     * Constructs a new CredentialRecordImpl from the attestation object and WebAuthn (Passkey) specific data.
     *
     * @param attestationObject the attestation object containing authenticator data and attestation statement
     * @param clientData the client data collected during the credential creation process, may be null
     * @param clientExtensions the client extension outputs from the credential creation process, may be null
     * @param transports the set of authenticator transport methods supported, may be null
     */
    public CredentialRecordImpl(
            @NotNull AttestationObject attestationObject,
            @Nullable CollectedClientData clientData,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports) {
        super(attestationObject);
        this.clientData = clientData;
        this.clientExtensions = clientExtensions;
        this.transports = transports;
    }

    /**
     * Constructs a new CredentialRecordImpl with explicitly specified parameters for both core credential properties
     * and WebAuthn (Passkey) specific data.
     *
     * @param attestationStatement    the attestation statement, may be null
     * @param uvInitialized           the user verification initialization status, may be null for backward compatibility
     * @param backupEligible          the backup eligibility status, may be null for backward compatibility
     * @param backupState             the backup state, may be null for backward compatibility
     * @param counter                 the signature counter value
     * @param attestedCredentialData  the attested credential data, must not be null
     * @param authenticatorExtensions the authenticator extensions, may be null
     * @param clientData              the client data collected during the credential creation process, may be null
     * @param clientExtensions        the client extension outputs from the credential creation process, may be null
     * @param transports              the set of authenticator transport methods supported, may be null
     */
    public CredentialRecordImpl(
            @Nullable AttestationStatement attestationStatement,
            @Nullable Boolean uvInitialized,
            @Nullable Boolean backupEligible,
            @Nullable Boolean backupState,
            long counter,
            @NotNull AttestedCredentialData attestedCredentialData,
            @Nullable AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions,
            @Nullable CollectedClientData clientData,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports) {
        super(attestationStatement, uvInitialized, backupEligible, backupState, counter, attestedCredentialData, authenticatorExtensions);
        this.clientData = clientData;
        this.clientExtensions = clientExtensions;
        this.transports = transports;
    }

    /**
     * {@inheritDoc}}
     */
    @Override
    public @Nullable CollectedClientData getClientData() {
        return clientData;
    }

    /**
     * {@inheritDoc}}
     */
    @Override
    public @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    /**
     * {@inheritDoc}}
     */
    @Override
    public @Nullable Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    /**
     * {@inheritDoc}}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CredentialRecordImpl that = (CredentialRecordImpl) o;
        return Objects.equals(clientData, that.clientData) && Objects.equals(clientExtensions, that.clientExtensions) && Objects.equals(transports, that.transports);
    }

    /**
     * {@inheritDoc}}
     */
    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), clientData, clientExtensions, transports);
    }
}
