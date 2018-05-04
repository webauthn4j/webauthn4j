package com.webauthn4j.test.platform;

public class AuthenticatorSelectionCriteria {

    private AuthenticatorAttachment authenticatorAttachment;
    private boolean requireResidentKey;
    private UserVerificationRequirement userVerificationRequirement = UserVerificationRequirement.PREFERRED;

    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public void setAuthenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
        this.authenticatorAttachment = authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

    public UserVerificationRequirement getUserVerificationRequirement() {
        return userVerificationRequirement;
    }

    public void setUserVerificationRequirement(UserVerificationRequirement userVerificationRequirement) {
        this.userVerificationRequirement = userVerificationRequirement;
    }
}
