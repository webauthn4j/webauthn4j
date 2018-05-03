package integration;

import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.anchor.WebAuthnTrustAnchorService;
import com.webauthn4j.anchor.WebAuthnTrustAnchorServiceImpl;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.authenticator.model.WebAuthnModelAuthenticatorAdaptor;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidatorImpl;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;
import org.junit.Test;

import java.util.Arrays;

public class UserVerifyingAuthenticatorRegistrationValidationTest {

    private Origin origin = new Origin("http://localhost");
    private WebAuthnModelAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnModelAuthenticatorAdaptor();
    private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
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
    public void validate_test(){
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }
}
