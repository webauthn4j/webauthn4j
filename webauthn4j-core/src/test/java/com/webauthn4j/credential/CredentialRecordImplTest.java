package com.webauthn4j.credential;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class CredentialRecordImplTest {

    private AttestationObject attestationObject;
    private CollectedClientData clientData;
    private AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private Set<AuthenticatorTransport> transports;

    @BeforeEach
    void setUp() {
        attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        clientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        transports = new HashSet<>();
    }

    @Test
    void shouldCreateCredentialRecordWithValidParameters() {
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
    void shouldCreateCredentialRecordWithEmptyTransports() {
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                new HashSet<>()
        );

        assertThat(credentialRecord.getTransports()).isEmpty();
    }

    @Test
    void shouldBeEqualWhenAllPropertiesAreEqual() {
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

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void shouldNotBeEqualWhenClientDataDiffers() {
        CredentialRecord instanceA = new CredentialRecordImpl(
                attestationObject,
                clientData,
                clientExtensions,
                transports
        );
        CredentialRecord instanceB = new CredentialRecordImpl(
                attestationObject,
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                clientExtensions,
                transports
        );

        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    void shouldHandleNullClientExtensions() {
        assertThatCode(() -> new CredentialRecordImpl(
                attestationObject,
                clientData,
                null,
                transports
        )).doesNotThrowAnyException();
    }
}