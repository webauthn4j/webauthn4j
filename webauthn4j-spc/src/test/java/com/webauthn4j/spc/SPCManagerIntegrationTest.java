package com.webauthn4j.spc;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.converter.jackson.SPCJSONModule;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.SPCRegistrationParameters;
import com.webauthn4j.spc.data.client.*;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import com.webauthn4j.verifier.exception.InconsistentClientDataTypeException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.util.Collections;

import static org.assertj.core.api.Assertions.*;

class SPCManagerIntegrationTest {

    private final Origin origin = new Origin("https://merchant.example");
    private final String rpId = "example.com";

    private final ObjectConverter spcObjectConverter = createSPCObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(spcObjectConverter);
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(spcObjectConverter);

    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);

    private final SPCManager spcManager = new SPCManager(spcObjectConverter);

    private static ObjectConverter createSPCObjectConverter() {
        return SPCManager.createObjectConverter();
    }

    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    @Test
    void registration_should_succeed_with_payment_client_data() {
        Challenge challenge = new DefaultChallenge();
        CollectedClientPaymentData paymentClientData = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE,
                challenge,
                origin,
                null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(TestDataUtil.createEC2COSEPublicKey())
        );

        RegistrationEmulationOption option = new RegistrationEmulationOption();
        option.setCollectedClientDataOverrideEnabled(true);
        option.setCollectedClientData(paymentClientData);

        var credentialCreationOptions = createCredentialCreationOptions(challenge);
        var response = clientPlatform.create(credentialCreationOptions, option, null);

        RegistrationRequest registrationRequest = new RegistrationRequest(
                response.getResponse().getAttestationObject(),
                response.getResponse().getClientDataJSON()
        );

        ServerProperty serverProperty = ServerProperty.builder().origin(origin).rpId(rpId).challenge(challenge).build();
        SPCRegistrationParameters params = new SPCRegistrationParameters(
                serverProperty,
                credentialCreationOptions.getPubKeyCredParams()
        );

        assertThatCode(() -> spcManager.verify(registrationRequest, params)).doesNotThrowAnyException();
    }

    @Test
    void registration_should_fail_without_payment_client_data() {
        Challenge challenge = new DefaultChallenge();
        Origin clientOrigin = clientPlatform.getOrigin();
        var credentialCreationOptions = createCredentialCreationOptions(challenge);
        var response = clientPlatform.create(credentialCreationOptions);

        RegistrationRequest registrationRequest = new RegistrationRequest(
                response.getResponse().getAttestationObject(),
                response.getResponse().getClientDataJSON()
        );

        ServerProperty serverProperty = ServerProperty.builder().origin(clientOrigin).rpId(rpId).challenge(challenge).build();
        SPCRegistrationParameters params = new SPCRegistrationParameters(
                serverProperty,
                credentialCreationOptions.getPubKeyCredParams()
        );

        assertThatThrownBy(() -> spcManager.verify(registrationRequest, params))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("CollectedClientPaymentData");
    }

    @Test
    void authentication_should_succeed_with_valid_spc_data() {
        Challenge challenge = new DefaultChallenge();
        CredentialRecord credentialRecord = createCredentialRecord(challenge);

        Challenge authChallenge = new DefaultChallenge();
        CollectedClientPaymentData paymentClientData = createPaymentClientData(authChallenge);
        var publicKeyCredential = getCredential(authChallenge, paymentClientData);

        AuthenticationRequest request = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                publicKeyCredential.getResponse().getSignature()
        );

        ServerProperty serverProperty = ServerProperty.builder().origin(origin).rpId(rpId).challenge(authChallenge).topOrigin(origin).build();
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                serverProperty, credentialRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );

        assertThatCode(() -> spcManager.verify(request, params)).doesNotThrowAnyException();
    }

    @Test
    void authentication_should_fail_with_wrong_total() {
        Challenge challenge = new DefaultChallenge();
        CredentialRecord credentialRecord = createCredentialRecord(challenge);

        Challenge authChallenge = new DefaultChallenge();
        CollectedClientPaymentData paymentClientData = createPaymentClientData(authChallenge);
        var publicKeyCredential = getCredential(authChallenge, paymentClientData);

        AuthenticationRequest request = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                publicKeyCredential.getResponse().getSignature()
        );

        ServerProperty serverProperty = ServerProperty.builder().origin(origin).rpId(rpId).challenge(authChallenge).topOrigin(origin).build();
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                serverProperty, credentialRecord,
                new PaymentCurrencyAmount("USD", "999.99"),
                INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );

        assertThatThrownBy(() -> spcManager.verify(request, params))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("total");
    }

    @Test
    void authentication_should_fail_with_non_payment_client_data() {
        Challenge challenge = new DefaultChallenge();
        CredentialRecord credentialRecord = createCredentialRecord(challenge);

        Challenge authChallenge = new DefaultChallenge();
        CollectedClientData standardClientData = clientPlatform.createCollectedClientData(
                ClientDataType.WEBAUTHN_GET, authChallenge);
        var publicKeyCredential = clientPlatform.get(
                createCredentialRequestOptions(authChallenge), standardClientData);

        AuthenticationRequest request = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                publicKeyCredential.getResponse().getSignature()
        );

        ServerProperty serverProperty = ServerProperty.builder().origin(origin).rpId(rpId).challenge(authChallenge).topOrigin(origin).build();
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                serverProperty, credentialRecord,
                TOTAL, INSTRUMENT, null, null
        );

        assertThatThrownBy(() -> spcManager.verify(request, params))
                .isInstanceOf(InconsistentClientDataTypeException.class);
    }

    @Test
    void parse_should_return_authentication_data_with_payment_client_data() {
        Challenge challenge = new DefaultChallenge();
        createCredentialRecord(challenge);

        Challenge authChallenge = new DefaultChallenge();
        CollectedClientPaymentData paymentClientData = createPaymentClientData(authChallenge);
        var publicKeyCredential = getCredential(authChallenge, paymentClientData);

        AuthenticationRequest request = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                publicKeyCredential.getResponse().getSignature()
        );

        AuthenticationData result = spcManager.parse(request);

        assertThat(result.getCollectedClientData()).isInstanceOf(CollectedClientPaymentData.class);
        CollectedClientPaymentData parsed = (CollectedClientPaymentData) result.getCollectedClientData();
        assertThat(parsed.getPayment()).isInstanceOf(CollectedClientAdditionalPaymentData.class);
        CollectedClientAdditionalPaymentData paymentData = (CollectedClientAdditionalPaymentData) parsed.getPayment();
        assertThat(paymentData.getTotal()).isEqualTo(TOTAL);
        assertThat(paymentData.getInstrument()).isEqualTo(INSTRUMENT);
        assertThat(paymentData.getRpId()).isEqualTo(rpId);
    }

    private CollectedClientPaymentData createPaymentClientData(Challenge challenge) {
        return new CollectedClientPaymentData(
                ClientDataType.create("payment.get"),
                challenge,
                origin,
                null, null, null,
                new CollectedClientAdditionalPaymentData(
                        rpId, new Origin("https://merchant.example"),
                        "Merchant Shop", new Origin("https://merchant.example"),
                        null, TOTAL, INSTRUMENT, null
                )
        );
    }

    private PublicKeyCredentialRequestOptions createCredentialRequestOptions(Challenge challenge) {
        return new PublicKeyCredentialRequestOptions(
                challenge, 0L, rpId, null,
                UserVerificationRequirement.REQUIRED, null
        );
    }

    private com.webauthn4j.data.PublicKeyCredential<AuthenticatorAssertionResponse, com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput>
    getCredential(Challenge challenge, CollectedClientData clientData) {
        return clientPlatform.get(createCredentialRequestOptions(challenge), clientData);
    }

    private PublicKeyCredentialCreationOptions createCredentialCreationOptions(Challenge challenge) {
        return new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM, true,
                        UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<>()
        );
    }

    private CredentialRecord createCredentialRecord(Challenge challenge) {
        var credentialCreationOptions = createCredentialCreationOptions(challenge);
        var response = clientPlatform.create(credentialCreationOptions);
        var registrationResponse = response.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(registrationResponse.getAttestationObject());
        var clientData = collectedClientDataConverter.convert(registrationResponse.getClientDataJSON());
        return new CredentialRecordImpl(attestationObject, clientData, response.getClientExtensionResults(), registrationResponse.getTransports());
    }
}
