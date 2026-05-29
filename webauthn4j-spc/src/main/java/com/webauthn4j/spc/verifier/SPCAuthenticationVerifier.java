package com.webauthn4j.spc.verifier;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.client.CollectedClientAdditionalPaymentData;
import com.webauthn4j.spc.data.client.CollectedClientPaymentData;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.CustomAuthenticationVerifier;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * Verifies SPC-specific fields in an authentication assertion.
 *
 * <p>This verifier implements the SPC-specific verification steps defined in:
 * <ul>
 *   <li><a href="https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260528/#sctn-relying-party-operations">
 *       SPC § 9 SPC Relying Party Operations</a></li>
 *   <li><a href="https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260528/#sctn-verifying-assertion">
 *       SPC § 9.1 Verifying an Authentication Assertion</a></li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260528/#sctn-verifying-assertion">SPC § 9.1</a>
 */
public class SPCAuthenticationVerifier implements CustomAuthenticationVerifier {

    @Override
    public void verify(@NotNull AuthenticationObject authenticationObject) {

        //spec| § 9.1 Verifying an Authentication Assertion
        //spec| In order to perform an authentication ceremony for Secure Payment Confirmation,
        //spec| the Relying Party MUST proceed as follows:

        //spec| Step 1
        //spec| Let credential be a PublicKeyCredential returned from a successful invocation of the
        //spec| Secure Payment Confirmation payment handler by the SPC caller.
        //      (This step is done on caller side and out of WebAuthn4J responsibility.)

        //spec| Step 2
        //spec| Perform steps 3-21 as specified in WebAuthn § 7.2, with the following changes:
        //      (Steps 3-21 of WebAuthn § 7.2 are handled by AuthenticationDataVerifier.)

        //spec|   In step 5, verify that credential.id identifies one of the public key credentials
        //spec|   provided to the SPC caller by the Relying Party.
        //        (Handled by AuthenticationDataVerifier. The caller should set
        //         AuthenticationParameters.allowCredentials to the expected credential IDs as needed.)

        //spec|   In step 11, verify that the value of C.type is the string "payment.get".
        //        (Handled by AuthenticationDataVerifier.setExpectedClientDataType(), configured by SPCManager.)

        //spec|   In step 12, verify that the value of C.challenge equals the base64url encoding of the
        //spec|   challenge provided to the SPC caller by the Relying Party.
        //        (Handled by AuthenticationDataVerifier via the standard WebAuthn flow.)

        //spec|   In step 13, verify that the value of C.origin matches the origin that the Relying Party
        //spec|   expects SPC to have been called from.
        //        (Handled by AuthenticationDataVerifier via the standard WebAuthn flow.)

        //spec|   After step 13, insert the following steps:

        if (!(authenticationObject.getAuthenticationParameters() instanceof SPCAuthenticationParameters)) {
            throw new ConstraintViolationException(
                    "AuthenticationParameters must be an instance of SPCAuthenticationParameters for SPC authentication.");
        }
        SPCAuthenticationParameters spcParameters =
                (SPCAuthenticationParameters) authenticationObject.getAuthenticationParameters();

        if (!(authenticationObject.getCollectedClientData() instanceof CollectedClientPaymentData)) {
            throw new ConstraintViolationException(
                    "CollectedClientData must be an instance of CollectedClientPaymentData for SPC authentication.");
        }

        CollectedClientPaymentData paymentClientData =
                (CollectedClientPaymentData) authenticationObject.getCollectedClientData();

        if (!(paymentClientData.getPayment() instanceof CollectedClientAdditionalPaymentData)) {
            throw new ConstraintViolationException(
                    "CollectedClientPaymentData.payment must be an instance of CollectedClientAdditionalPaymentData for SPC authentication.");
        }

        CollectedClientAdditionalPaymentData paymentData =
                (CollectedClientAdditionalPaymentData) paymentClientData.getPayment();

        //spec| Verify that the value of C.payment.rpId matches the Relying Party's origin.
        verifyRpId(paymentData.getRpId(), spcParameters.getServerProperty().getRpId());

        //spec|   Verify that the value of C.payment.topOrigin matches the top-level origin that the Relying Party expects.
        verifyTopOrigin(paymentData.getTopOrigin(), spcParameters.getServerProperty().getTopOriginPredicate());

        //spec| Verify that the value of C.payment.payeeName matches the name of the payee
        //spec| that should have been displayed to the user, if any.
        verifyPayeeName(paymentData.getPayeeName(), spcParameters.getExpectedPayeeName());

        //spec| Verify that the value of C.payment.payeeOrigin matches the origin of the payee
        //spec| that should have been displayed to the user, if any.
        verifyPayeeOrigin(paymentData.getPayeeOrigin(), spcParameters.getExpectedPayeeOrigin());

        //spec| Verify that the value of C.payment.paymentEntitiesLogos is a strict and ordered subset
        //spec| of the logos that should have been displayed to the user, if any.
        verifyPaymentEntitiesLogos(paymentData.getPaymentEntitiesLogos(), spcParameters.getExpectedPaymentEntitiesLogos());

        //spec| Verify that the value of C.payment.total matches the transaction amount
        //spec| that should have been displayed to the user.
        verifyTotal(paymentData.getTotal(), spcParameters.getExpectedTotal());

        //spec| Verify that the value of C.payment.instrument matches the payment instrument details
        //spec| that should have been displayed to the user.
        verifyInstrument(paymentData.getInstrument(), spcParameters.getExpectedInstrument());

        // TODO: Verify Browser Bound Key (BBK) signature.
        // Requires SPCCredentialRecord (extending CredentialRecord) to carry the stored browserBoundPublicKey,
        // then verify BrowserBoundSignature over clientDataJSON using that key. See SPC spec §9.
    }

    void verifyRpId(@NotNull String actual, @NotNull String expected) {
        if (!Objects.equals(actual, expected)) {
            throw new ConstraintViolationException(
                    String.format("payment.rpId '%s' does not match expected '%s'.", actual, expected));
        }
    }

    void verifyTopOrigin(@NotNull Origin actual, @Nullable OriginPredicate topOriginPredicate) {
        if (topOriginPredicate == null) {
            throw new ConstraintViolationException(
                    "ServerProperty.topOriginPredicate must be configured for SPC authentication. " +
                    "Use ServerProperty.Builder.topOrigin() or topOriginPredicate() to set the expected top-level origin.");
        }
        if (!topOriginPredicate.test(actual)) {
            throw new ConstraintViolationException(
                    String.format("payment.topOrigin '%s' does not match the expected top-level origin.", actual));
        }
    }

    void verifyTotal(@NotNull PaymentCurrencyAmount actual, @NotNull PaymentCurrencyAmount expected) {
        if (!Objects.equals(actual, expected)) {
            throw new ConstraintViolationException(
                    String.format("payment.total '%s' does not match expected '%s'.", actual, expected));
        }
    }

    void verifyInstrument(@NotNull PaymentCredentialInstrument actual, @NotNull PaymentCredentialInstrument expected) {
        if (!Objects.equals(actual, expected)) {
            throw new ConstraintViolationException(
                    String.format("payment.instrument '%s' does not match expected '%s'.", actual, expected));
        }
    }

    void verifyPayeeName(@Nullable String actual, @Nullable String expected) {
        if (expected != null && !Objects.equals(actual, expected)) {
            throw new ConstraintViolationException(
                    String.format("payment.payeeName '%s' does not match expected '%s'.", actual, expected));
        }
    }

    void verifyPayeeOrigin(@Nullable Origin actual, @Nullable Origin expected) {
        if (expected != null && !Objects.equals(actual, expected)) {
            throw new ConstraintViolationException(
                    String.format("payment.payeeOrigin '%s' does not match expected '%s'.", actual, expected));
        }
    }

    void verifyPaymentEntitiesLogos(@Nullable List<PaymentEntityLogo> actual, @Nullable List<PaymentEntityLogo> expected) {
        if (expected != null) {
            if (actual == null || !isOrderedSubset(actual, expected)) {
                throw new ConstraintViolationException(
                        "payment.paymentEntitiesLogos is not a strict and ordered subset of expected logos.");
            }
        }
    }

    static boolean isOrderedSubset(
            @NotNull List<PaymentEntityLogo> actual,
            @NotNull List<PaymentEntityLogo> expected) {
        int expectedIdx = 0;
        for (PaymentEntityLogo logo : actual) {
            boolean found = false;
            while (expectedIdx < expected.size()) {
                if (Objects.equals(logo, expected.get(expectedIdx))) {
                    found = true;
                    expectedIdx++;
                    break;
                }
                expectedIdx++;
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
}
