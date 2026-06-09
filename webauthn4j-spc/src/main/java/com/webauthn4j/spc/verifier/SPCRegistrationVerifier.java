package com.webauthn4j.spc.verifier;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.spc.data.client.CollectedClientAdditionalPaymentRegistrationData;
import com.webauthn4j.spc.data.client.CollectedClientPaymentData;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

/**
 * Verifies SPC-specific constraints during credential registration.
 *
 * <p>The SPC specification (§ 3 Registration) requires that the credential is created with
 * the {@code payment} extension, which results in a {@link CollectedClientPaymentData}
 * containing a {@link CollectedClientAdditionalPaymentRegistrationData}.
 * This verifier ensures that structure is present.
 *
 * <p>The standard WebAuthn registration verification steps (§ 7.1) are handled by
 * {@link com.webauthn4j.verifier.RegistrationDataVerifier}.
 *
 * @see <a href="https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260528/#sctn-registration">SPC § 3 Registration</a>
 * @see <a href="https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260528/#sctn-payment-extension-registration">
 *     SPC § 5 WebAuthn Extension - "payment" (Registration)</a>
 */
public class SPCRegistrationVerifier implements CustomRegistrationVerifier {

    @Override
    public void verify(@NotNull RegistrationObject registrationObject) {
        CollectedClientData collectedClientData = registrationObject.getCollectedClientData();

        //spec| § 5 WebAuthn Extension - "payment" (Registration processing)
        //spec| The client extension creates a CollectedClientPaymentData with a payment field
        //spec| containing a CollectedClientAdditionalPaymentRegistrationData.
        //      Verify that the clientDataJSON was produced by the payment extension.

        if (!(collectedClientData instanceof CollectedClientPaymentData)) {
            throw new ConstraintViolationException(
                    "CollectedClientData must be an instance of CollectedClientPaymentData for SPC registration.");
        }

        CollectedClientPaymentData paymentData = (CollectedClientPaymentData) collectedClientData;

        if (!(paymentData.getPayment() instanceof CollectedClientAdditionalPaymentRegistrationData)) {
            throw new ConstraintViolationException(
                    "CollectedClientPaymentData.payment must be an instance of CollectedClientAdditionalPaymentRegistrationData for SPC registration.");
        }
    }
}
