package com.webauthn4j.async.verifier;

import com.webauthn4j.async.verifier.attestation.statement.AttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import com.webauthn4j.verifier.exception.InconsistentClientDataTypeException;
import com.webauthn4j.verifier.internal.*;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class RegistrationDataAsyncVerifier {

    private static final int DEFAULT_MAX_CREDENTIAL_ID_LENGTH = 1023;

    // ~ Instance fields
    // ================================================================================================
    private final ClientExtensionAsyncVerifier clientExtensionAsyncVerifier = new ClientExtensionAsyncVerifier();
    private final AuthenticatorExtensionAsyncVerifier authenticatorExtensionAsyncVerifier = new AuthenticatorExtensionAsyncVerifier();

    private final List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers;

    private final AttestationAsyncVerifier attestationAsyncVerifier;

    private OriginAsyncVerifier originVerifier = new OriginAsyncVerifierImpl();

    private int maxCredentialIdLength = DEFAULT_MAX_CREDENTIAL_ID_LENGTH;

    public RegistrationDataAsyncVerifier(
            List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
            CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
            SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
            List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers, ObjectConverter objectConverter) {

        AssertUtil.notNull(attestationStatementAsyncVerifiers, "attestationStatementAsyncVerifiers must not be null");
        AssertUtil.notNull(certPathTrustworthinessAsyncVerifier, "certPathTrustworthinessAsyncVerifier must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessAsyncVerifier, "selfAttestationTrustworthinessAsyncVerifier must not be null");
        AssertUtil.notNull(customRegistrationAsyncVerifiers, "customRegistrationAsyncVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.attestationAsyncVerifier = new AttestationAsyncVerifier(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier);

        this.customRegistrationAsyncVerifiers = customRegistrationAsyncVerifiers;
    }

    public CompletionStage<RegistrationData> verify(RegistrationData registrationData, RegistrationParameters registrationParameters) {
        RegistrationDataVerification registrationDataVerification = new RegistrationDataVerification(registrationData, registrationParameters);
        return registrationDataVerification.execute();
    }

    public OriginAsyncVerifier getOriginVerifier() {
        return originVerifier;
    }

    public void setOriginVerifier(OriginAsyncVerifier originVerifier) {
        this.originVerifier = originVerifier;
    }

    public int getMaxCredentialIdLength() {
        return maxCredentialIdLength;
    }

    public void setMaxCredentialIdLength(int maxCredentialIdLength) {
        this.maxCredentialIdLength = maxCredentialIdLength;
    }

    private class RegistrationDataVerification{

        private final RegistrationData registrationData;
        private final RegistrationParameters registrationParameters;

        private CollectedClientData collectedClientData;
        private AttestationObject attestationObject;
        private RegistrationObject registrationObject;
        private AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData;

        private RegistrationDataVerification(RegistrationData registrationData, RegistrationParameters registrationParameters) {
            this.registrationData = registrationData;
            this.registrationParameters = registrationParameters;
        }

        public CompletionStage<RegistrationData> execute(){
            return execStep1toStep8()
                    .thenCompose(unused -> this.execStep9())
                    .thenCompose(unused -> this.execStep10toStep19())
                    .thenCompose(unused -> this.execStep20())
                    .thenCompose(unused -> this.execStep21toStep24AndStep28())
                    .thenCompose(unused -> this.execStep25toStep27())
                    .thenApply(unused -> registrationData);
        }

        private CompletionStage<Void> execStep1toStep8(){

            BeanAssertUtil.validate(registrationData);
            AssertUtil.notNull(registrationParameters, "registrationParameters must not be null");

            //spec| Step1
            //spec| Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
            //      (This step is done on client side and out of WebAuthn4J responsibility.)

            //spec| Step2
            //spec| Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise.
            //spec| If the promise is rejected, abort the ceremony with a user-visible error,
            //spec| or otherwise guide the user experience as might be determinable from the context available in the rejected promise.
            //spec| For example if the promise is rejected with an error code equivalent to "InvalidStateError",
            //spec| the user might be instructed to use a different authenticator.
            //spec| For information on different error contexts and the circumstances leading to them, see § 6.3.2 The authenticatorMakeCredential Operation.
            //      (This step is done on client side and out of WebAuthn4J responsibility.)

            //spec| Step3
            //spec| Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.
            //      (This step is done on client side and out of WebAuthn4J responsibility.)

            //spec| Step4
            //spec| Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = registrationData.getClientExtensions();

            //spec| Step5
            //spec| Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
            //      (This step is done on caller.)

            attestationObject = registrationData.getAttestationObject();

            // attestedCredentialData must be present on registration
            if (attestationObject.getAuthenticatorData().getAttestedCredentialData() == null) {
                throw new ConstraintViolationException("attestedCredentialData must not be null on registration");
            }

            //spec| Step6
            //spec| Let C, the client data claimed as collected during the credential creation,
            //spec| be the result of running an implementation-specific JSON parser on JSONtext.
            collectedClientData = registrationData.getCollectedClientData();

            authenticatorData = attestationObject.getAuthenticatorData();
            ServerProperty serverProperty = registrationParameters.getServerProperty();
            Set<AuthenticatorTransport> transports = registrationData.getTransports();

            byte[] clientDataBytes = registrationData.getCollectedClientDataBytes();
            byte[] attestationObjectBytes = registrationData.getAttestationObjectBytes();

            registrationObject = new RegistrationObject(
                    attestationObject,
                    attestationObjectBytes,
                    collectedClientData,
                    clientDataBytes,
                    clientExtensions,
                    transports,
                    serverProperty
            );

            //spec| Step7
            //spec| Verify that the value of C.type is webauthn.create.
            if (!Objects.equals(collectedClientData.getType(), ClientDataType.WEBAUTHN_CREATE)) {
                throw new InconsistentClientDataTypeException("ClientData.type must be 'create' on registration, but it isn't.");
            }
            //spec| Step8
            //spec| Verify that the value of C.challenge equals the base64url encoding of options.challenge.
            ChallengeVerifier.verify(collectedClientData, registrationObject.getServerProperty());
            return CompletableFuture.completedFuture(null);
        }

        //spec| Step9
        //spec| Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        private CompletionStage<Void> execStep9(){
            return originVerifier.verify(registrationObject);
        }

        @SuppressWarnings("java:S1874")
        private CompletionStage<Void> execStep10toStep19(){
            //spec| (Level2) Step10 (Kept for backward compatibility)
            //spec| Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
            //spec| which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
            //spec| C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            //noinspection deprecation
            TokenBindingVerifier.verify(collectedClientData.getTokenBinding(), registrationObject.getServerProperty().getTokenBindingId());

            //spec| Step10
            //spec| If C.topOrigin is present:
            //spec|   - Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
            //spec|   - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See § 13.4.9 Validating the origin of a credential for guidance.
            //TODO: Once Chrome starts supporting topOrigin, implement topOrigin verification

            //spec| Step11
            //spec| Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.

            //spec| Step12
            //spec| Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
            //spec| obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
            //      (This step is done on caller.)

            //spec| Step13
            //spec| Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
            RpIdHashVerifier.verify(authenticatorData.getRpIdHash(), registrationObject.getServerProperty());

            //spec| Step14, 15
            //spec| Verify that the UP bit of the flags in authData is set.
            //spec| If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
            UPUVFlagsVerifier.verify(authenticatorData, registrationParameters.isUserPresenceRequired(), registrationParameters.isUserVerificationRequired());

            //spec| Step16
            //spec| If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
            BEBSFlagsVerifier.verify(authenticatorData);

            //spec| Step17
            //spec| If the Relying Party uses the credential’s backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData.
            //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

            //spec| Step18
            //spec| If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData.
            //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)


            //spec| Step19
            //spec| Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
            COSEAlgorithmIdentifier alg = authenticatorData.getAttestedCredentialData().getCOSEKey().getAlgorithm();
            List<PublicKeyCredentialParameters> pubKeyCredParams = registrationParameters.getPubKeyCredParams();
            COSEAlgorithmIdentifierVerifier.verify(alg, pubKeyCredParams);


            return CompletableFuture.completedFuture(null);
        }

        private CompletionStage<Void> execStep20(){
            //spec| Step20
            //spec| Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected,
            //spec| considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions,
            //spec| i.e., those that were not specified as part of options.extensions.
            //spec| In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = registrationObject.getClientExtensions();
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = authenticatorData.getExtensions();
            return clientExtensionAsyncVerifier.verify(clientExtensions).thenCompose(unused-> authenticatorExtensionAsyncVerifier.verify(authenticatorExtensions));
        }

        private CompletionStage<Void> execStep21toStep24AndStep28(){
            //spec| Step21-24

            //spec| Step28
            //spec| If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above,
            //spec| the Relying Party SHOULD fail the registration ceremony.
            //      (This step is implemented in attestationVerifier#verify)
            return attestationAsyncVerifier.verify(registrationObject);
        }

        private CompletionStage<Void> execStep25toStep27(){
            //spec| Step25
            //spec| Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
            CredentialIdLengthVerifier.verify(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(), maxCredentialIdLength);

            //spec| Step26
            //spec| Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
            //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

            //spec| Step27
            //spec| If the attestation statement attStmt verified successfully and is found to be trustworthy,
            //spec| then create and store a new credential record in the user account that was denoted in options.user,
            //spec| with the following contents:
            //spec| type
            //spec|     credential.type.
            //spec| id
            //spec|     credential.id or credential.rawId, whichever format is preferred by the Relying Party.
            //spec| publicKey
            //spec|     The credential public key in authData.
            //spec| signCount
            //spec|     authData.signCount.
            //spec| uvInitialized
            //spec|     The value of the UV flag in authData.
            //spec| transports
            //spec|     The value returned from response.getTransports().
            //spec| backupEligible
            //spec|     The value of the BE flag in authData.
            //spec| backupState
            //spec|     The value of the BS flag in authData.
            //spec| The new credential record MAY also include the following OPTIONAL contents:
            //spec| attestationObject
            //spec|     response.attestationObject.
            //spec| attestationClientDataJSON
            //spec|     response.clientDataJSON.
            //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)


            // verify with custom logic
            Iterator<CustomRegistrationAsyncVerifier> iterator = customRegistrationAsyncVerifiers.iterator();
            CompletableFuture<Void> completableFuture = CompletableFuture.completedFuture(null);
            while(iterator.hasNext()){
                CustomRegistrationAsyncVerifier customRegistrationAsyncVerifier = iterator.next();
                completableFuture = completableFuture.thenAccept(unused -> customRegistrationAsyncVerifier.verify(registrationObject));
            }
            return CompletableFuture.completedFuture(null);
        }
    }
}
