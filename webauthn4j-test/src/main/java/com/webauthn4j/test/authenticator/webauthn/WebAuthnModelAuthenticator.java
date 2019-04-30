/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.SupportedExtensionsExtensionClientInput;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.SupportedExtensionsExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.exception.*;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.KeyUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.SecureRandomFactory;
import com.webauthn4j.util.WIP;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.*;

@WIP
public abstract class WebAuthnModelAuthenticator implements WebAuthnAuthenticator{

    private CborConverter cborConverter = new CborConverter();

    AAGUID aaguid;
    private boolean capableOfUserVerification;
    private int counter;
    private Map<CredentialMapKey, PublicKeyCredentialSource> credentialMap;
    private boolean countUpEnabled = true;

    private AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(cborConverter); // TODO: inject objectMapper from constructor

    public WebAuthnModelAuthenticator(boolean capableOfUserVerification, AAGUID aaguid, int counter) {
        this.capableOfUserVerification = capableOfUserVerification;
        this.aaguid = aaguid;
        this.counter = counter;
        this.credentialMap = new HashMap<>();
    }

    public WebAuthnModelAuthenticator() {
        this(
                true,
                AAGUID.ZERO,
                0
        );
    }

    public PublicKeyCredentialSource lookup(byte[] credentialId) {

        if (!isCapableOfStoringClientSideResidentCredential()) {
            PublicKeyCredentialSource credentialSource = null; //TODO: decrypt credentialId into a credSource;
            return credentialSource;
        }
        for (Map.Entry<CredentialMapKey, PublicKeyCredentialSource> entry : credentialMap.entrySet()) {
            if (Arrays.equals(credentialId, entry.getValue().getId())) {
                return entry.getValue();
            }
        }
        return null;
    }

    public MakeCredentialResponse makeCredential(MakeCredentialRequest makeCredentialRequest, RegistrationEmulationOption registrationEmulationOption) {

        PublicKeyCredentialRpEntity rpEntity = makeCredentialRequest.getRpEntity();

        // Check if all the supplied parameters are syntactically well-formed and of the correct length.
        // If not, return an error code equivalent to "UnknownError" and terminate the operation.
        //TODO

        // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters
        // in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError"
        // and terminate the operation.
        Optional<PublicKeyCredentialParameters> optionalPublicKeyCredentialParameters =
                makeCredentialRequest.getCredTypesAndPublicKeyAlgs().stream().filter(this::isCapableOfHandling).findFirst();
        PublicKeyCredentialParameters publicKeyCredentialParameters;
        if (optionalPublicKeyCredentialParameters.isPresent()) {
            publicKeyCredentialParameters = optionalPublicKeyCredentialParameters.get();
        } else {
            throw new NotSupportedException("Specified PublicKeyCredentialParameters are not supported");
        }

        // For each descriptor of excludeCredentialDescriptorList:
        List<PublicKeyCredentialDescriptor> descriptors = makeCredentialRequest.getExcludeCredentialDescriptorList();
        if (descriptors == null) {
            descriptors = Collections.emptyList();
        }
        for (PublicKeyCredentialDescriptor descriptor : descriptors) {
            PublicKeyCredentialSource publicKeyCredentialSource = lookup(descriptor.getId());
            // If looking up descriptor.id in this authenticator returns non-null, and the returned item's RP ID
            // and type match rpEntity.id and excludeCredentialDescriptorList.type respectively,
            // then obtain user consent for creating a new credential.
            // The method of obtaining user consent MUST include a test of user presence.
            if (publicKeyCredentialSource != null) {
                if (publicKeyCredentialSource.getRpId().equals(rpEntity.getId()) &&
                        publicKeyCredentialSource.getType().equals(descriptor.getType())) {
                    boolean userConsent = true;
                    // If the user
                    // confirms consent to create a new credential
                    if (userConsent) {
                        throw new InvalidStateException("");
                    }
                    // does not consent to create a new credential
                    else {
                        throw new NotAllowedException("User consent is required");
                    }
                }
            }
        }
        // If requireResidentKey is true and the authenticator cannot store a Client-side-resident Credential Private Key,
        // return an error code equivalent to "ConstraintError" and terminate the operation.
        if (makeCredentialRequest.isRequireResidentKey() && !isCapableOfStoringClientSideResidentCredential()) {
            throw new ConstraintException("Authenticator isn't capable of storing client-side resident credential");
        }
        // If requireUserVerification is true and the authenticator cannot perform user verification,
        // return an error code equivalent to "ConstraintError" and terminate the operation.
        if (makeCredentialRequest.isRequireUserVerification() && !isCapableOfUserVerification()) {
            throw new ConstraintException("Authenticator isn't capable of user verification");
        }

        // Obtain user consent for creating a new credential.
        // The prompt for obtaining this consent is shown by the authenticator if it has its own output capability,
        // or by the user agent otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name, userEntity.name
        // and userEntity.displayName, if possible.
        boolean userVerification = true;
        boolean userConsent = true;

        // If requireUserVerification is true, the method of obtaining user consent MUST include user verification.
        // If requireUserPresence is true, the method of obtaining user consent MUST include a test of user presence.
        // If the user does not consent or if user verification fails, return an error code equivalent to
        // "NotAllowedError" and terminate the operation.
        if (makeCredentialRequest.isRequireUserVerification() && !userVerification) {
            throw new NotAllowedException("User is not verified.");
        }
        if (makeCredentialRequest.isRequireUserPresence() && !userConsent) {
            throw new NotAllowedException("User doesn't resolve consent.");
        }

        // Once user consent has been obtained, generate a new credential object:
        byte[] credentialId;
        // Let (publicKey, privateKey) be a new pair of cryptographic keys using the combination of
        // PublicKeyCredentialType and cryptographic parameters represented by the first item in
        // credTypesAndPubKeyAlgs that is supported by this authenticator.
        PrivateKey credentialPrivateKey;
        CredentialPublicKey credentialPublicKey;
        try {
            KeyPair keyPair = KeyUtil.createECKeyPair();
            credentialPrivateKey = keyPair.getPrivate();
            credentialPublicKey = EC2CredentialPublicKey.create((ECPublicKey) keyPair.getPublic());

            // Let userHandle be userEntity.id.
            byte[] userHandle = makeCredentialRequest.getUserEntity().getId();
            // Let credentialSource be a new public key credential source with the fields:
            PublicKeyCredentialSource credentialSource = new PublicKeyCredentialSource();
            credentialSource.setType(PublicKeyCredentialType.PUBLIC_KEY);
            credentialSource.setPrivateKey(credentialPrivateKey);
            credentialSource.setRpId(rpEntity.getId());
            credentialSource.setUserHandle(userHandle);
            credentialSource.setOtherUI(null);

            // If requireResidentKey is true or the authenticator chooses to create a Client-side-resident
            // Credential Private Key:
            if (makeCredentialRequest.isRequireResidentKey()) {
                // Let credentialId be a new credential id.
                credentialId = SecureRandomFactory.getSecureRandom().randomBytes(32);
                // Set credentialSource.id to credentialId.
                credentialSource.setId(credentialId);
                // Let credentials be this authenticator’s credentials map.
                Map<CredentialMapKey, PublicKeyCredentialSource> credentials = credentialMap;
                credentials.put(new CredentialMapKey(rpEntity.getId(), userHandle), credentialSource);
            }
            // Otherwise:
            else {
                // Let credentialId be the result of serializing and encrypting credentialSource
                // so that only this authenticator can decrypt it.
                credentialId = null; // TODO
            }
        }
        // If any error occurred while creating the new credential object,
        // return an error code equivalent to "UnknownError" and terminate the operation.
        catch (RuntimeException e) {
            throw new WebAuthnModelException(e);
        }

        // Let processedExtensions be the result of authenticator extension processing for each
        // supported extension identifier -> authenticator extension input in extensions.
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = makeCredentialRequest.getExtensions();
        if (extensions == null) {
            extensions = new AuthenticationExtensionsClientInputs<>();
        }
        Map<String, RegistrationExtensionAuthenticatorOutput> processedExtensions = new HashMap<>();
        for (Map.Entry<String, RegistrationExtensionClientInput> entry : extensions.entrySet()) {
            String extensionIdentifier = entry.getKey();
            if (extensionIdentifier.equals(SupportedExtensionsExtensionClientInput.ID)) {
                processedExtensions.put(SupportedExtensionsExtensionClientInput.ID, new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList("exts")));
            }
        }

        // If the authenticator supports:
        // a per-RP ID signature counter
        //   allocate the counter, associate it with the RP ID, and initialize the counter value as zero.
        // a global signature counter
        //   Use the global signature counter's actual value when generating authenticator data.
        // a per credential signature counter
        //   allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        countUp(); // TODO: counter mode

        // Let attestedCredentialData be the attested credential data byte array including the credentialId and publicKey.
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpEntity.getId().getBytes(StandardCharsets.UTF_8));
        byte flag = BIT_AT;
        if (userConsent) flag |= BIT_UP;
        if (userVerification) flag |= BIT_UV;
        if (!processedExtensions.isEmpty()) flag |= BIT_ED;

        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(aaguid, credentialId, credentialPublicKey);

        // Let authenticatorData be the byte array specified in §6.1 Authenticator data,
        // including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData =
                new AuthenticatorData<>(rpIdHash, flag, counter, attestedCredentialData, new AuthenticationExtensionsAuthenticatorOutputs<>(processedExtensions));

        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, makeCredentialRequest.getHash());



        AttestationStatement attestationStatement = generateAttestationStatement(signedData, registrationEmulationOption);

        // Return the attestation object for the new credential created by the procedure specified in
        // §6.3.4 Generating an Attestation Object using an authenticator-chosen attestation statement format,
        // authenticatorData, and hash. For more details on attestation, see §6.3 Attestation.
        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);


        // On successful completion of this operation, the authenticator returns the attestation object to the client.
        MakeCredentialResponse makeCredentialResponse = new MakeCredentialResponse();
        makeCredentialResponse.setAttestationObject(attestationObject);
        return makeCredentialResponse;
    }

    public MakeCredentialResponse makeCredential(MakeCredentialRequest makeCredentialRequest) {
        return makeCredential(makeCredentialRequest, new RegistrationEmulationOption());
    }

    public GetAssertionResponse getAssertion(GetAssertionRequest getAssertionRequest, AuthenticationEmulationOption authenticationEmulationOption) {

        byte flags = 0;

        // Check if all the supplied parameters are syntactically well-formed and of the correct length.
        // If not, return an error code equivalent to "UnknownError" and terminate the operation.
        //TODO

        //Let credentialOptions be a new empty set of public key credential sources.
        List<PublicKeyCredentialSource> credentialOptions = new ArrayList<>();

        //If allowCredentialDescriptorList was supplied, then for each descriptor of allowCredentialDescriptorList:
        List<PublicKeyCredentialDescriptor> allowCredentialDescriptorList = getAssertionRequest.getAllowCredentialDescriptorList();
        if (allowCredentialDescriptorList != null && !allowCredentialDescriptorList.isEmpty()) {
            for (PublicKeyCredentialDescriptor credentialDescriptor : getAssertionRequest.getAllowCredentialDescriptorList()) {
                // Let credSource be the result of looking up descriptor.id in this authenticator.
                PublicKeyCredentialSource credSource = lookup(credentialDescriptor.getId());
                if (credSource != null) {
                    credentialOptions.add(credSource);
                }
            }
        }
        // Otherwise (allowCredentialDescriptorList was not supplied),
        // for each key -> credSource of this authenticator’s credentials map, append credSource to credentialOptions.
        else {
            for (Map.Entry<CredentialMapKey, PublicKeyCredentialSource> entry : credentialMap.entrySet()) {
                credentialOptions.add(entry.getValue());
            }
        }
        // Remove any items from credentialOptions whose rpId is not equal to rpId.
        credentialOptions = credentialOptions.stream().filter(item -> item.getRpId().equals(getAssertionRequest.getRpId())).collect(Collectors.toList());

        // If credentialOptions is now empty, return an error code equivalent to "NotAllowedError" and terminate the operation.
        if (credentialOptions.isEmpty()) {
            throw new NotAllowedException("No matching authenticator found");
        }
        // Prompt the user to select a public key credential source selectedCredential from credentialOptions.
        // Obtain user consent for using selectedCredential. The prompt for obtaining this consent may be shown by
        // the authenticator if it has its own output capability, or by the user agent otherwise.

        // If requireUserVerification is true, the method of obtaining user consent MUST include user verification.
        if (getAssertionRequest.isRequireUserVerification()) {
            flags |= BIT_UV;
        }
        // If requireUserPresence is true, the method of obtaining user consent MUST include a test of user presence.
        if (getAssertionRequest.isRequireUserPresence()) {
            flags |= BIT_UP;
        }
        // If the user does not consent, return an error code equivalent to "NotAllowedError" and terminate the operation.

        PublicKeyCredentialSource selectedCredential = credentialOptions.get(0); //TODO

        // Let processedExtensions be the result of authenticator extension processing for each supported
        // extension identifier -> authenticator extension input in extensions.
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> processedExtensions = new AuthenticationExtensionsAuthenticatorOutputs<>();
        if (!processedExtensions.isEmpty()) {
            flags |= BIT_ED;
        }


        // Increment the RP ID-associated signature counter or the global signature counter value,
        // depending on which approach is implemented by the authenticator, by some positive value.
        countUp();

        // Let authenticatorData be the byte array specified in §6.1 Authenticator data including processedExtensions,
        // if any, as the extensions and excluding attestedCredentialData.
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(getAssertionRequest.getRpId().getBytes(StandardCharsets.UTF_8));
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorDataObject = new AuthenticatorData<>(rpIdHash, flags, counter, processedExtensions);
        byte[] authenticatorData = authenticatorDataConverter.convert(authenticatorDataObject);

        // Let signature be the assertion signature of the concatenation authenticatorData || hash using
        // the privateKey of selectedCredential as shown in Figure 2, below. A simple, undelimited concatenation is
        // safe to use here because the authenticator data describes its own length.
        // The hash of the serialized client data (which potentially has a variable length) is always the last element.
        byte[] clientDataHash = getAssertionRequest.getHash();
        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
        byte[] signature = TestDataUtil.calculateSignature(selectedCredential.getPrivateKey(), signedData);
        // If any error occurred while generating the assertion signature,
        // return an error code equivalent to "UnknownError" and terminate the operation.

        // Return to the user agent:
        GetAssertionResponse getAssertionResponse = new GetAssertionResponse();
        getAssertionResponse.setCredentialId(selectedCredential.getId());
        getAssertionResponse.setAuthenticatorData(authenticatorData);
        getAssertionResponse.setSignature(signature);
        getAssertionResponse.setUserHandle(selectedCredential.getUserHandle());
        return getAssertionResponse;
    }

    public GetAssertionResponse getAssertion(GetAssertionRequest getAssertionRequest) {
        return getAssertion(getAssertionRequest, new AuthenticationEmulationOption());
    }

    public boolean isCapableOfUserVerification() {
        return capableOfUserVerification;
    }

    public boolean isCapableOfStoringClientSideResidentCredential() {
        return true;
    }

    private boolean isCapableOfHandling(PublicKeyCredentialParameters publicKeyCredentialParameters) {
        return publicKeyCredentialParameters.getType() == PublicKeyCredentialType.PUBLIC_KEY &&
                publicKeyCredentialParameters.getAlg() == COSEAlgorithmIdentifier.ES256;
    }

    public boolean isCountUpEnabled() {
        return countUpEnabled;
    }

    public void setCountUpEnabled(boolean countUpEnabled) {
        this.countUpEnabled = countUpEnabled;
    }

    protected abstract AttestationStatement generateAttestationStatement(byte[] signedData, RegistrationEmulationOption registrationEmulationOption);

    private byte[] getSignedData(byte[] authenticatorData, byte[] clientDataHash) {
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private void countUp() {
        if (isCountUpEnabled()) {
            counter++;
        }
    }
}
