package com.webauthn4j.spc.verifier;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.converter.jackson.SPCJSONModule;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.client.*;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SPCRegistrationVerifierTest {

    private final SPCRegistrationVerifier target = new SPCRegistrationVerifier();
    private final ObjectConverter objectConverter = createObjectConverter();

    private static ObjectConverter createObjectConverter() {
        return SPCManager.createObjectConverter();
    }

    @Test
    void verify_should_succeed_with_CollectedClientPaymentData() {
        RegistrationObject registrationObject = createRegistrationObject(
                createPaymentClientData(ClientDataType.WEBAUTHN_CREATE)
        );

        assertThatCode(() -> target.verify(registrationObject))
                .doesNotThrowAnyException();
    }

    @Test
    void verify_should_throw_when_CollectedClientData_is_not_payment() {
        CollectedClientData plainClientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_CREATE);
        RegistrationObject registrationObject = createRegistrationObject(plainClientData);

        assertThatThrownBy(() -> target.verify(registrationObject))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("CollectedClientPaymentData");
    }

    @Test
    void verify_should_throw_when_payment_is_authentication_data() {
        CollectedClientPaymentData paymentData = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE,
                new DefaultChallenge(),
                new Origin("https://bank.example"),
                null, null, null,
                new CollectedClientAdditionalPaymentData(
                        "bank.example", new Origin("https://merchant.example"),
                        null, null, null,
                        new PaymentCurrencyAmount("USD", "5.00"),
                        new PaymentCredentialInstrument("Card", "https://icon.png"),
                        null
                )
        );
        RegistrationObject registrationObject = createRegistrationObject(paymentData);

        assertThatThrownBy(() -> target.verify(registrationObject))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("CollectedClientAdditionalPaymentRegistrationData");
    }

    private CollectedClientPaymentData createPaymentClientData(ClientDataType type) {
        return new CollectedClientPaymentData(
                type,
                new DefaultChallenge(),
                new Origin("https://bank.example"),
                null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(TestDataUtil.createEC2COSEPublicKey())
        );
    }

    private RegistrationObject createRegistrationObject(CollectedClientData clientData) {
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = new AttestationObjectConverter(objectConverter).convertToBytes(attestationObject);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        ServerProperty serverProperty = TestDataUtil.createServerProperty();
        RegistrationParameters registrationParameters = TestDataUtil.createRegistrationParameters(serverProperty);
        return new RegistrationObject(
                attestationObject, attestationObjectBytes,
                clientData, clientDataBytes,
                clientExtensions, transports,
                registrationParameters, Instant.now()
        );
    }
}
