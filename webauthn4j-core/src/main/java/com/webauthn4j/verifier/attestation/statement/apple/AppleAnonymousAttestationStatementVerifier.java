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

package com.webauthn4j.verifier.attestation.statement.apple;

import com.webauthn4j.converter.internal.asn1.ASN1Primitive;
import com.webauthn4j.converter.internal.asn1.ASN1Sequence;
import com.webauthn4j.data.attestation.statement.AppleAnonymousAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.PublicKeyMismatchException;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;

public class AppleAnonymousAttestationStatementVerifier extends AbstractStatementVerifier<AppleAnonymousAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================


    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.", registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }

        AppleAnonymousAttestationStatement attestationStatement =
                (AppleAnonymousAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        verifyAttestationStatementNotNull(attestationStatement);
        verifyNonce(registrationObject);

        verifyPublicKey(registrationObject, attestationStatement);

        return AttestationType.BASIC;
    }

    void verifyAttestationStatementNotNull(AppleAnonymousAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }

    private void verifyNonce(@NotNull CoreRegistrationObject registrationObject) {
        AppleAnonymousAttestationStatement attestationStatement = (AppleAnonymousAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] nonce = getNonce(registrationObject);
        byte[] extensionValue = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getExtensionValue("1.2.840.113635.100.8.2");
        byte[] extracted;

        try {
            ASN1Primitive extensionEnvelope = ASN1Primitive.parse(extensionValue);
            ASN1Sequence sequence = (ASN1Sequence) extensionEnvelope.getValueAsASN1();
            ASN1Sequence innerSequence = (ASN1Sequence) sequence.get(0);
            ASN1Primitive firstItem = (ASN1Primitive) innerSequence.get(0);
            extracted =  firstItem.getValue();

//            Asn1OctetString extensionEnvelope = new Asn1OctetString();
//            extensionEnvelope.decode(extensionValue);
//            extensionEnvelope.getValue();
//            byte[] extensionEnvelopeValue = extensionEnvelope.getValue();
//            Asn1Container container = (Asn1Container) Asn1Parser.parse(ByteBuffer.wrap(extensionEnvelopeValue));
//            Asn1ParseResult firstElement = container.getChildren().get(0);
//            Asn1OctetString octetString = new Asn1OctetString();
//            octetString.decode(firstElement);
//            extracted = octetString.getValue();
        } catch (RuntimeException e) {
            throw new BadAttestationStatementException("Failed to extract nonce from Apple anonymous attestation statement.", e);
        }
        // As nonce is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(extracted, nonce)) {
            throw new BadAttestationStatementException("nonce doesn't match.");
        }
    }

    private @NotNull byte[] getNonce(@NotNull CoreRegistrationObject registrationObject) {
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = registrationObject.getClientDataHash();
        byte[] nonceToHash = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
        return MessageDigestUtil.createSHA256().digest(nonceToHash);
    }

    private void verifyPublicKey(@NotNull CoreRegistrationObject registrationObject, @NotNull AppleAnonymousAttestationStatement attestationStatement) {
        PublicKey publicKeyInEndEntityCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        //noinspection ConstantConditions as null check is already done in caller.
        PublicKey publicKeyInCredentialData = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getPublicKey();
        if (!publicKeyInEndEntityCert.equals(publicKeyInCredentialData)) {
            throw new PublicKeyMismatchException("The public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
        }
    }

}