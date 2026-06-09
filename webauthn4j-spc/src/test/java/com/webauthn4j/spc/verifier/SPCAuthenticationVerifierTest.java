package com.webauthn4j.spc.verifier;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.credential.BrowserBoundKey;
import com.webauthn4j.spc.credential.SPCCredentialRecord;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.client.*;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SPCAuthenticationVerifierTest {

    private final SPCAuthenticationVerifier target = new SPCAuthenticationVerifier();
    private final ObjectConverter objectConverter = createObjectConverter();

    private static ObjectConverter createObjectConverter() {
        return SPCManager.createObjectConverter();
    }

    private static final String RP_ID = "fancybank.example";
    private static final Origin MERCHANT_ORIGIN = new Origin("https://merchant.example");
    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    // --- verifyRpId ---

    @Test
    void verifyRpId_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyRpId(RP_ID, RP_ID)).doesNotThrowAnyException();
    }

    @Test
    void verifyRpId_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyRpId("wrong.example", RP_ID))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("rpId");
    }

    // --- verifyTopOrigin ---

    @Test
    void verifyTopOrigin_should_succeed_when_matching() {
        OriginPredicate predicate = buildTopOriginPredicate(MERCHANT_ORIGIN);
        assertThatCode(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), predicate))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyTopOrigin_should_throw_when_not_matching() {
        OriginPredicate predicate = buildTopOriginPredicate(new Origin("https://other.example"));
        assertThatThrownBy(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), predicate))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("topOrigin");
    }

    @Test
    void verifyTopOrigin_should_throw_when_predicate_is_not_configured() {
        assertThatThrownBy(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), null))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("topOriginPredicate must be configured");
    }

    // --- verifyTotal ---

    @Test
    void verifyTotal_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyTotal(TOTAL, TOTAL)).doesNotThrowAnyException();
    }

    @Test
    void verifyTotal_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyTotal(new PaymentCurrencyAmount("USD", "10.00"), TOTAL))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("total");
    }

    // --- verifyInstrument ---

    @Test
    void verifyInstrument_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyInstrument(INSTRUMENT, INSTRUMENT)).doesNotThrowAnyException();
    }

    @Test
    void verifyInstrument_should_throw_when_not_matching() {
        PaymentCredentialInstrument wrong = new PaymentCredentialInstrument("Other Card", "https://other.example/icon.png");
        assertThatThrownBy(() -> target.verifyInstrument(wrong, INSTRUMENT))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("instrument");
    }

    // --- verifyPayeeName ---

    @Test
    void verifyPayeeName_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyPayeeName("Merchant Shop", "Merchant Shop")).doesNotThrowAnyException();
    }

    @Test
    void verifyPayeeName_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyPayeeName("Evil Shop", "Merchant Shop"))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("payeeName");
    }

    @Test
    void verifyPayeeName_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPayeeName("Any Name", null)).doesNotThrowAnyException();
    }

    // --- verifyPayeeOrigin ---

    @Test
    void verifyPayeeOrigin_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyPayeeOrigin(new Origin("https://merchant.example"), new Origin("https://merchant.example"))).doesNotThrowAnyException();
    }

    @Test
    void verifyPayeeOrigin_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyPayeeOrigin(new Origin("https://evil.example"), new Origin("https://merchant.example")))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("payeeOrigin");
    }

    @Test
    void verifyPayeeOrigin_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPayeeOrigin(new Origin("https://any.example"), null)).doesNotThrowAnyException();
    }

    // --- verifyPaymentEntitiesLogos ---

    @Test
    void verifyPaymentEntitiesLogos_should_succeed_when_ordered_subset() {
        PaymentEntityLogo logoA = new PaymentEntityLogo("https://a.png", "A");
        PaymentEntityLogo logoB = new PaymentEntityLogo("https://b.png", "B");
        PaymentEntityLogo logoC = new PaymentEntityLogo("https://c.png", "C");
        assertThatCode(() -> target.verifyPaymentEntitiesLogos(List.of(logoA, logoC), List.of(logoA, logoB, logoC)))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyPaymentEntitiesLogos_should_throw_when_not_ordered_subset() {
        PaymentEntityLogo logoA = new PaymentEntityLogo("https://a.png", "A");
        PaymentEntityLogo logoB = new PaymentEntityLogo("https://b.png", "B");
        PaymentEntityLogo logoC = new PaymentEntityLogo("https://c.png", "C");
        assertThatThrownBy(() -> target.verifyPaymentEntitiesLogos(List.of(logoC, logoA), List.of(logoA, logoB, logoC)))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("paymentEntitiesLogos");
    }

    @Test
    void verifyPaymentEntitiesLogos_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPaymentEntitiesLogos(null, null)).doesNotThrowAnyException();
    }

    // --- verify (integration) ---

    @Test
    void verify_should_succeed_with_matching_payment_data() {
        AuthenticationObject authObject = createAuthenticationObject(
                RP_ID, TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"), null,
                createParams(TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"))
        );
        assertThatCode(() -> target.verify(authObject)).doesNotThrowAnyException();
    }

    @Test
    void verify_should_throw_when_not_SPCAuthenticationParameters() {
        CollectedClientData plainClientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET);
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(plainClientData);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(objectConverter).convert(authenticatorData);
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(createServerProperty(), TestDataUtil.createCredentialRecord(), null, false, true);
        AuthenticationObject plainObject = new AuthenticationObject(
                new byte[32], authenticatorData, authenticatorDataBytes,
                plainClientData, clientDataBytes, new AuthenticationExtensionsClientOutputs<>(),
                authenticationParameters
        );
        assertThatThrownBy(() -> target.verify(plainObject))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("SPCAuthenticationParameters");
    }

    // --- helpers ---

    private SPCAuthenticationParameters createParams(
            PaymentCurrencyAmount total, PaymentCredentialInstrument instrument,
            String payeeName, Origin payeeOrigin) {
        return new SPCAuthenticationParameters(
                createServerProperty(), createSPCCredentialRecord(),
                total, instrument, payeeName, payeeOrigin
        );
    }

    private static TestSPCCredentialRecord createSPCCredentialRecord() {
        return new TestSPCCredentialRecord(TestDataUtil.createCredentialRecord(), Collections.emptyList());
    }

    private static OriginPredicate buildTopOriginPredicate(Origin topOrigin) {
        return ServerProperty.builder()
                .origin(MERCHANT_ORIGIN).rpId(RP_ID).challenge(new DefaultChallenge())
                .topOrigin(topOrigin).build().getTopOriginPredicate();
    }

    private ServerProperty createServerProperty() {
        return ServerProperty.builder()
                .origin(MERCHANT_ORIGIN).rpId(RP_ID).challenge(new DefaultChallenge())
                .topOrigin(MERCHANT_ORIGIN).build();
    }

    private AuthenticationObject createAuthenticationObject(
            String rpId, PaymentCurrencyAmount total, PaymentCredentialInstrument instrument,
            String payeeName, Origin payeeOrigin, List<PaymentEntityLogo> logos,
            SPCAuthenticationParameters params) {
        CollectedClientPaymentData clientData = new CollectedClientPaymentData(
                ClientDataType.create("payment.get"),
                new DefaultChallenge(),
                MERCHANT_ORIGIN,
                true, MERCHANT_ORIGIN, null,
                new CollectedClientAdditionalPaymentData(
                        rpId, new Origin("https://merchant.example"),
                        payeeName, payeeOrigin, logos,
                        total, instrument, null
                )
        );
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(clientData);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(objectConverter).convert(authenticatorData);
        return new AuthenticationObject(
                new byte[32], authenticatorData, authenticatorDataBytes,
                clientData, clientDataBytes, new AuthenticationExtensionsClientOutputs<>(),
                params
        );
    }

    private CollectedClientAdditionalPaymentData createPaymentDataWithBrowserBoundKey(
            com.webauthn4j.data.attestation.authenticator.COSEKey browserBoundPublicKey) {
        return new CollectedClientAdditionalPaymentData(
                RP_ID, MERCHANT_ORIGIN,
                "Merchant Shop", new Origin("https://merchant.example"), null,
                TOTAL, INSTRUMENT, browserBoundPublicKey
        );
    }

    private AuthenticationObject createAuthenticationObjectWithCredentialRecord(SPCCredentialRecord credentialRecord) {
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                createServerProperty(), credentialRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );
        return createAuthenticationObject(
                RP_ID, TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"), null, params
        );
    }

    // --- verifyBrowserBoundKey ---

    @Test
    void verifyBrowserBoundKey_should_skip_when_browserBoundKeys_is_empty() {
        CredentialRecord base = TestDataUtil.createCredentialRecord();
        TestSPCCredentialRecord spcRecord = new TestSPCCredentialRecord(base, Collections.emptyList());
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                createServerProperty(), spcRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );
        AuthenticationObject authObject = createAuthenticationObjectWithCredentialRecord(spcRecord);
        CollectedClientAdditionalPaymentData paymentData = createPaymentDataWithBrowserBoundKey(null);
        assertThatCode(() -> target.verifyBrowserBoundKey(authObject, paymentData, params))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyBrowserBoundKey_should_throw_when_presentedKey_is_missing() {
        CredentialRecord base = TestDataUtil.createCredentialRecord();
        BrowserBoundKey storedKey = new BrowserBoundKey(TestDataUtil.createEC2COSEPublicKey());
        TestSPCCredentialRecord spcRecord = new TestSPCCredentialRecord(base, List.of(storedKey));
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                createServerProperty(), spcRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );
        AuthenticationObject authObject = createAuthenticationObjectWithCredentialRecord(spcRecord);
        CollectedClientAdditionalPaymentData paymentData = createPaymentDataWithBrowserBoundKey(null);
        assertThatThrownBy(() -> target.verifyBrowserBoundKey(authObject, paymentData, params))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("missing");
    }

    @Test
    void verifyBrowserBoundKey_should_throw_when_presentedKey_is_unknown() throws Exception {
        CredentialRecord base = TestDataUtil.createCredentialRecord();
        // Generate two distinct key pairs so stored and presented keys differ
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair storedKeyPair = keyGen.generateKeyPair();
        KeyPair presentedKeyPair = keyGen.generateKeyPair();
        EC2COSEKey storedCoseKey = EC2COSEKey.create((ECPublicKey) storedKeyPair.getPublic(), COSEAlgorithmIdentifier.ES256);
        EC2COSEKey presentedCoseKey = EC2COSEKey.create((ECPublicKey) presentedKeyPair.getPublic(), COSEAlgorithmIdentifier.ES256);

        BrowserBoundKey storedKey = new BrowserBoundKey(storedCoseKey);
        TestSPCCredentialRecord spcRecord = new TestSPCCredentialRecord(base, List.of(storedKey));
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                createServerProperty(), spcRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );
        AuthenticationObject authObject = createAuthenticationObjectWithCredentialRecord(spcRecord);
        CollectedClientAdditionalPaymentData paymentData = createPaymentDataWithBrowserBoundKey(presentedCoseKey);
        assertThatThrownBy(() -> target.verifyBrowserBoundKey(authObject, paymentData, params))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("does not match");
    }

    // --- verifyBrowserBoundSignature ---

    @Test
    void verifyBrowserBoundSignature_should_succeed_with_valid_signature() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();
        EC2COSEKey coseKey = EC2COSEKey.create((ECPublicKey) keyPair.getPublic(), COSEAlgorithmIdentifier.ES256);

        byte[] clientDataJSON = "{\"type\":\"payment.get\"}".getBytes();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(clientDataJSON);
        byte[] signatureBytes = sig.sign();

        assertThatCode(() -> target.verifyBrowserBoundSignature(coseKey, signatureBytes, clientDataJSON))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyBrowserBoundSignature_should_throw_with_invalid_signature() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();
        EC2COSEKey coseKey = EC2COSEKey.create((ECPublicKey) keyPair.getPublic(), COSEAlgorithmIdentifier.ES256);

        byte[] clientDataJSON = "{\"type\":\"payment.get\"}".getBytes();
        byte[] invalidSignature = new byte[]{0x00, 0x01, 0x02, 0x03};

        assertThatThrownBy(() -> target.verifyBrowserBoundSignature(coseKey, invalidSignature, clientDataJSON))
                .isInstanceOf(BadSignatureException.class);
    }

    // --- verifyBrowserBoundKey with custom handler ---

    @Test
    void verifyBrowserBoundKey_with_custom_handler() throws Exception {
        AtomicBoolean handlerCalled = new AtomicBoolean(false);
        SPCAuthenticationVerifier verifierWithCustomHandler = new SPCAuthenticationVerifier();
        verifierWithCustomHandler.setBrowserBoundKeyHandler(event -> handlerCalled.set(true));

        CredentialRecord base = TestDataUtil.createCredentialRecord();
        // Generate two distinct key pairs so stored and presented keys differ
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair storedKeyPair = keyGen.generateKeyPair();
        KeyPair presentedKeyPair = keyGen.generateKeyPair();
        EC2COSEKey storedCoseKey = EC2COSEKey.create((ECPublicKey) storedKeyPair.getPublic(), COSEAlgorithmIdentifier.ES256);
        EC2COSEKey presentedCoseKey = EC2COSEKey.create((ECPublicKey) presentedKeyPair.getPublic(), COSEAlgorithmIdentifier.ES256);

        BrowserBoundKey storedKey = new BrowserBoundKey(storedCoseKey);
        TestSPCCredentialRecord spcRecord = new TestSPCCredentialRecord(base, List.of(storedKey));
        SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                createServerProperty(), spcRecord,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example")
        );
        AuthenticationObject authObject = createAuthenticationObjectWithCredentialRecord(spcRecord);
        CollectedClientAdditionalPaymentData paymentData = createPaymentDataWithBrowserBoundKey(presentedCoseKey);

        assertThatCode(() -> verifierWithCustomHandler.verifyBrowserBoundKey(authObject, paymentData, params))
                .doesNotThrowAnyException();
        assertThatCode(() -> {
            if (!handlerCalled.get()) {
                throw new AssertionError("Custom handler was not called");
            }
        }).doesNotThrowAnyException();
    }

    // --- Test helper: SPCCredentialRecord implementation ---

    private static class TestSPCCredentialRecord extends CredentialRecordImpl implements SPCCredentialRecord {
        private final List<BrowserBoundKey> browserBoundKeys;

        TestSPCCredentialRecord(CredentialRecord base, List<BrowserBoundKey> browserBoundKeys) {
            super(
                    base.getAttestationStatement(),
                    base.isUvInitialized(),
                    base.isBackupEligible(),
                    base.isBackedUp(),
                    base.getCounter(),
                    base.getAttestedCredentialData(),
                    base.getAuthenticatorExtensions(),
                    base.getClientData(),
                    base.getClientExtensions(),
                    base.getTransports()
            );
            this.browserBoundKeys = browserBoundKeys;
        }

        @Override
        public @NotNull List<BrowserBoundKey> getBrowserBoundKeys() {
            return browserBoundKeys;
        }
    }
}
