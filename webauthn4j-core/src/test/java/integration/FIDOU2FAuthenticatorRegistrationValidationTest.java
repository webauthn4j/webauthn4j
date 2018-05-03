package integration;

import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.anchor.WebAuthnTrustAnchorService;
import com.webauthn4j.anchor.WebAuthnTrustAnchorServiceImpl;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidatorImpl;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;
import com.webauthn4j.validator.exception.*;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_CREATE;
import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;
import static org.mockito.Mockito.mock;

public class FIDOU2FAuthenticatorRegistrationValidationTest {

    private Origin origin = new Origin("http://localhost");
    private ClientPlatform clientPlatform = new ClientPlatform(origin);
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private TrustAnchorProvider trustAnchorProvider = TestUtil.createTrustAnchorProviderWith2tierTestRootCACertificate();
    private WebAuthnTrustAnchorService webAuthnTrustAnchorService = new WebAuthnTrustAnchorServiceImpl(trustAnchorProvider);
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
            Arrays.asList(noneAttestationStatementValidator, fidoU2FAttestationStatementValidator),
            new SelfAttestationTrustworthinessValidatorImpl(),
            new TrustAnchorCertPathTrustworthinessValidator(webAuthnTrustAnchorService),
            new ECDAATrustworthinessValidatorImpl()
    );

    @Test
    public void validate_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test
    public void validate_with_direct_attestation_conveyance_preference_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = MaliciousDataException.class)
    public void validate_with_bad_clientData_type_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(TYPE_WEBAUTHN_GET, challenge);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions, collectedClientData);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadChallengeException.class)
    public void validate_with_bad_challenge_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(badChallenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadOriginException.class)
    public void validate_with_bad_origin_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        Origin badOrigin = new Origin("http://bad.origin.example.com");
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        ClientPlatform clientPlatform = new ClientPlatform(badOrigin);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadRpIdException.class)
    public void validate_with_bad_rpId_test() {
        String rpId = "localhost";
        String badRpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(badRpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadAttestationStatementException.class)
    public void validate_with_bad_attestationStatement_test(){
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
                Collections.singletonList(fidoU2FAttestationStatementValidator),
                new SelfAttestationTrustworthinessValidatorImpl(),
                new TrustAnchorCertPathTrustworthinessValidator(mock(WebAuthnTrustAnchorService.class)),
                new ECDAATrustworthinessValidatorImpl()
        );
        target.validate(registrationContext);
    }

    @Test(expected = BadSignatureException.class)
    public void validate_invalid_format_attestation_signature_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        RegistrationEmulationOption registrationEmulationOption = new RegistrationEmulationOption();
        registrationEmulationOption.setSignatureOverrideEnabled(true);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions, registrationEmulationOption);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadSignatureException.class)
    public void validate_malicious_client_data_test() {
        Origin phishingSiteOrigin = new Origin("http://phishing.site.example.com");
        Origin validSiteOrigin = new Origin("http://valid.site.example.com");
        Origin phishingSiteClaimingOrigin = new Origin("http://valid.site.example.com");

        ClientPlatform clientPlatform = new ClientPlatform(phishingSiteOrigin); // client platform loads phishing site
        String rpId = "valid.site.example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "valid.site.example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);

        CollectedClientData maliciousClientData = new CollectedClientData(TYPE_WEBAUTHN_CREATE, challenge, phishingSiteClaimingOrigin, null);
        byte[] maliciousClientDataBytes = new CollectedClientDataConverter().convertToBytes(maliciousClientData);
        RelyingParty relyingParty = new RelyingParty(validSiteOrigin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(maliciousClientDataBytes, registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }




}
