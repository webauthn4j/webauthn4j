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

package com.webauthn4j.appattest.validator.attestation.statement.appleappattest;

import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.appattest.validator.DCRegistrationObject;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Validates that the specified {@link AttestationStatement} is a valid Apple App Attest attestation
 */
public class AppleAppAttestAttestationStatementValidator extends AbstractStatementValidator<AppleAppAttestAttestationStatement> {

    public static final String APPLE_CRED_CERT_EXTENSION_OID = "1.2.840.113635.100.8.2";

    @Override
    public AttestationType validate(@NonNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");

        if (!(registrationObject instanceof DCRegistrationObject)) {
            throw new IllegalArgumentException("registrationObject must be an instance of DCRegistrationObject.");
        }
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.",
                    registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }
        AppleAppAttestAttestationStatement attestationStatement = (AppleAppAttestAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        validateAttestationStatementNotNull(attestationStatement);

        validateX5c(attestationStatement);
        validateNonce(registrationObject);
        validatePublicKey(registrationObject);
        return AttestationType.BASIC;
    }

    void validateAttestationStatementNotNull(@Nullable AppleAppAttestAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }


    void validateX5c(@NonNull AppleAppAttestAttestationStatement attestationStatement) {
        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException(
                    "No attestation certificate is found in Apple App Attest attestation statement."
            );
        }
    }

    @Override
    public boolean supports(CoreRegistrationObject registrationObject) {
        return super.supports(registrationObject) && registrationObject instanceof DCRegistrationObject;
    }

    private void validateNonce(CoreRegistrationObject registrationObject) {
        AppleAppAttestAttestationStatement attestationStatement = getAttestationStatement(registrationObject);
        X509Certificate attestationCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
        byte[] actualNonce = extractNonce(attestationCertificate);

        byte[] clientDataHash = registrationObject.getClientDataHash();
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] composite = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
                .put(authenticatorData).put(clientDataHash).array();
        byte[] expectedNonce = MessageDigestUtil.createSHA256().digest(composite);

        // As nonce is known data to client side(potential attacker), there is no risk of timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual`
        if (!Arrays.equals(actualNonce, expectedNonce)) {
            throw new BadAttestationStatementException("App Attest nonce doesn't match.");
        }
    }

    private void validatePublicKey(CoreRegistrationObject registrationObject) {
        byte[] publicKey = ECUtil.createUncompressedPublicKey((ECPublicKey) getAttestationStatement(registrationObject).getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey());
        DCRegistrationObject dcRegistrationObject = (DCRegistrationObject) registrationObject;
        byte[] keyId = dcRegistrationObject.getKeyId();
        // As publicKey is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(MessageDigestUtil.createSHA256().digest(publicKey), keyId)) {
            throw new BadAttestationStatementException("key identifier doesn't match SHA-256 of the publickey");
        }
    }

    private AppleAppAttestAttestationStatement getAttestationStatement(CoreRegistrationObject registrationObject) {
        return (AppleAppAttestAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
    }

    byte[] extractNonce(X509Certificate attestationCertificate) {
        byte[] attestationExtensionBytes = attestationCertificate.getExtensionValue(APPLE_CRED_CERT_EXTENSION_OID);
        if (attestationExtensionBytes == null) {
            throw new BadAttestationStatementException("Apple X.509 extension not found");
        }

        Asn1OctetString envelope = new Asn1OctetString();
        try {
            envelope.decode(attestationExtensionBytes);
            Asn1Container container = (Asn1Container) Asn1Parser.parse(ByteBuffer.wrap(envelope.getValue()));
            Asn1OctetString subEnvelop = new Asn1OctetString();
            subEnvelop.decode(container.getChildren().get(0));
            return subEnvelop.getValue();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
