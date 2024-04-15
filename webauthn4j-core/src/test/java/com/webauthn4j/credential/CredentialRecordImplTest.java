package com.webauthn4j.credential;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialRecordImplTest {

    @Test
    void constructor_test(){
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        Set<AuthenticatorTransport> transports = new HashSet<>();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        assertThat(credentialRecord.getClientData()).isEqualTo(clientData);
        assertThat(credentialRecord.getClientExtensions()).isEqualTo(clientExtensions);
        assertThat(credentialRecord.getTransports()).isEqualTo(transports);
    }

    @Test
    void equals_hashCode_test(){
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        Set<AuthenticatorTransport> transports = new HashSet<>();
        CredentialRecord instanceA = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        CredentialRecord instanceB = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        assertThat(instanceA).isEqualTo(instanceB).hasSameHashCodeAs(instanceB);
    }

}