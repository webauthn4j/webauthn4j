/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import com.webauthn4j.anchor.CertFileTrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.*;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

public class DeviceCheckManagerSample {

    private Logger logger = LoggerFactory.getLogger(DeviceCheckManagerSample.class);

    private final DeviceCheckManager deviceCheckManager;

    public DeviceCheckManagerSample() {
        CertFileTrustAnchorsProvider certFileTrustAnchorsProvider = getAppleAppAttestCertFileTrustAnchorsProvider();
        deviceCheckManager = new DeviceCheckManager(new TrustAnchorCertPathTrustworthinessValidator(new TrustAnchorsResolverImpl(certFileTrustAnchorsProvider)));
    }

    public void attestationValidationSample() {

        // Client properties
        byte[] keyIdentifier = null; /* set keyIdentifier */
        byte[] attestationObject = null; /* set attestationObject */
        byte[] challenge = null; /* set challenge */
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);

        // Server properties
        String teamIdentifier = null /* set teamIdentifier */;
        String cfBundleIdentifier = null /* set cfBundleIdentifier */;
        DCServerProperty dcServerProperty = new DCServerProperty(teamIdentifier, cfBundleIdentifier, new DefaultChallenge(challenge));

        DCAttestationRequest dcAttestationRequest = new DCAttestationRequest(attestationObject, attestationObject, clientDataHash);
        DCAttestationParameters dcAttestationParameters = new DCAttestationParameters(dcServerProperty);
        DCAttestationData dcAttestationData;
        try {
            dcAttestationData = deviceCheckManager.parse(dcAttestationRequest);
        } catch (DataConversionException e) {
            // If you would like to handle Apple App Attest data structure parse error, please catch DataConversionException
            throw e;
        }
        try {
            deviceCheckManager.validate(dcAttestationData, dcAttestationParameters);
        } catch (ValidationException e) {
            // If you would like to handle Apple App Attest data validation error, please catch ValidationException
            throw e;
        }

        // please persist Authenticator object, which will be used in the authentication process.
        DCAppleDevice dcAppleDevice =
                new DCAppleDeviceImpl( // You may create your own Authenticator implementation to save friendly authenticator name
                        dcAttestationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                        dcAttestationData.getAttestationObject().getAttestationStatement(),
                        dcAttestationData.getAttestationObject().getAuthenticatorData().getSignCount(),
                        dcAttestationData.getAttestationObject().getAuthenticatorData().getExtensions()
                );
        save(dcAppleDevice); // please persist authenticator in your manner
    }


    public void authenticationValidationSample() {
        // Client properties
        byte[] credentialId = null /* set credentialId */;
        byte[] assertion = null /* set assertion */;
        byte[] clientDataHash = null /* set clientDataHash */;

        // Server properties
        String teamIdentifier = null /* set teamIdentifier */;
        String cfBundleIdentifier = null /* set cfBundleIdentifier */;
        byte[] challenge = null;
        DCServerProperty dcServerProperty = new DCServerProperty(teamIdentifier, cfBundleIdentifier, new DefaultChallenge(challenge));

        DCAppleDevice dcAppleDevice = load(credentialId); // please load authenticator object persisted in the attestation process in your manner

        DCAssertionRequest dcAssertionRequest =
                new DCAssertionRequest(
                        credentialId,
                        assertion,
                        clientDataHash
                );
        DCAssertionParameters dcAssertionParameters =
                new DCAssertionParameters(
                        dcServerProperty,
                        dcAppleDevice
                );

        DCAssertionData dcAssertionData;
        try {
            dcAssertionData = deviceCheckManager.parse(dcAssertionRequest);
        } catch (DataConversionException e) {
            // If you would like to handle Apple App Attest data structure parse error, please catch DataConversionException
            throw e;
        }
        try {
            deviceCheckManager.validate(dcAssertionData, dcAssertionParameters);
        } catch (ValidationException e) {
            // If you would like to handle Apple App Attest data validation error, please catch ValidationException
            throw e;
        }
        // please update the counter of the authenticator record
        updateCounter(
                dcAssertionData.getCredentialId(),
                dcAssertionData.getAuthenticatorData().getSignCount()
        );
    }


    private void save(DCAppleDevice dcAppleDevice) {
        // please persist in your manner
    }

    private DCAppleDevice load(byte[] credentialId) {
        return null; // please load DCAppleDevice in your manner
    }

    private void updateCounter(byte[] credentialId, long signCount) {
        // please update the counter of the authenticator record
        // authenticator should be resolved using following comparision:
        // Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId)
    }

    private CertFileTrustAnchorsProvider getAppleAppAttestCertFileTrustAnchorsProvider()  {
        CertFileTrustAnchorsProvider certFileTrustAnchorsProvider = new CertFileTrustAnchorsProvider();
        try {
            Path path = Paths.get(ClassLoader.getSystemResource("apple-app-attest/Apple_App_Attestation_Root_CA.pem").toURI());
            certFileTrustAnchorsProvider.setCertificates(Collections.singletonList(path));
            return certFileTrustAnchorsProvider;
        } catch (URISyntaxException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

}
