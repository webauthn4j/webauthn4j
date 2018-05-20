package integration.scenario;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticator;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.exception.*;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_CREATE;

public class FIDOU2FAuthenticatorAuthenticationValidationTest {

    private Origin origin = new Origin("http://example.com");
    private ClientPlatform clientPlatform = new ClientPlatform(origin, new FIDOU2FAuthenticatorAdaptor());
    private WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator();

    @Test
    public void validate_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = MaliciousDataException.class)
    public void validate_assertion_test_with_bad_clientData_type() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(TYPE_WEBAUTHN_CREATE, challenge); // bad clientData type
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = BadChallengeException.class)
    public void validate_assertion_with_bad_challenge_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                badChallenge, // bad challenge
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = BadOriginException.class)
    public void validate_assertion_with_bad_origin_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        clientPlatform.setOrigin(new Origin("https://bad.origin.example.com")); //bad origin
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = BadRpIdException.class)
    public void validate_assertion_with_bad_rpId_test() {
        String rpId = "example.com";
        String badRpId = "bad.rpId.example.net";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                badRpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = UserNotVerifiedException.class)
    public void validate_assertion_with_userVerificationRequired_option_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, true);
    }

    @Test(expected = UserNotPresentException.class)
    public void validate_assertion_with_UP_flag_off_test() {
        FIDOU2FAuthenticatorAdaptor fidou2FAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor();
        fidou2FAuthenticatorAdaptor.getFidoU2FAuthenticator().setFlags(FIDOU2FAuthenticator.FLAG_OFF);
        clientPlatform = new ClientPlatform(origin, fidou2FAuthenticatorAdaptor);
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = BadSignatureException.class)
    public void validate_assertion_with_bad_signature_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        new byte[32], //bad signature
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

    @Test(expected = MaliciousCounterValueException.class)
    public void validate_assertion_with_malicious_counter_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        serverProperty
                );
        Authenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        authenticator.setCounter(100); //set expected minimum counter bigger than that of actual authenticator
        target.validate(authenticationContext, authenticator, false);
    }

    private AttestationObject createAttestationObject(String rpId, Challenge challenge) {
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();
        return attestationObjectConverter.convert(registrationRequest.getAttestationObject());
    }

}
