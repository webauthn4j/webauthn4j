package com.webauthn4j.test.platform;

import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.client.challenge.Challenge;

import java.util.List;
import java.util.Map;

public class PublicKeyCredentialRequestOptions {

    private Challenge challenge;
    private long timeout;
    private String rpId;
    private List<PublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private Map<String, Extension> extensions;

    public PublicKeyCredentialRequestOptions(Challenge challenge,
                                             long timeout,
                                             String rpId,
                                             List<PublicKeyCredentialDescriptor> allowCredentials,
                                             UserVerificationRequirement userVerification,
                                             Map<String, Extension> extensions) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials;
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public long getTimeout() {
        return timeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public Map<String, Extension> getExtensions() {
        return extensions;
    }
}
