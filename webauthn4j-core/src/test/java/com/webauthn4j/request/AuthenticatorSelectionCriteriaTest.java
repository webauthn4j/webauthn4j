package com.webauthn4j.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

public class AuthenticatorSelectionCriteriaTest {

    @Test
    public void getter_test() {
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);
        assertAll(
                () -> assertThat(authenticatorSelectionCriteria.getAuthenticatorAttachment()).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM),
                () -> assertThat(authenticatorSelectionCriteria.isRequireResidentKey()).isEqualTo(true),
                () -> assertThat(authenticatorSelectionCriteria.getUserVerification()).isEqualTo(UserVerificationRequirement.REQUIRED)
        );
    }

    @Test
    public void equals_hashCode_test() {
        AuthenticatorSelectionCriteria instanceA
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);
        AuthenticatorSelectionCriteria instanceB
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}