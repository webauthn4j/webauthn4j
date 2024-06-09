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

// Some code fragment in this file is based on android key attestation sample provided by the Android Open Source Project.
// https://github.com/googlesamples/android-key-attestation

package com.webauthn4j.verifier.attestation.statement.androidkey;

import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.KeyDescriptionValidationException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

public class KeyDescriptionVerifier {

    public static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final int ATTESTATION_CHALLENGE_INDEX = 4;
    public static final int SW_ENFORCED_INDEX = 6;
    public static final int TEE_ENFORCED_INDEX = 7;
    public static final int KM_TAG_PURPOSE = 1;
    public static final int KM_TAG_ALL_APPLICATIONS = 600;
    public static final int KM_TAG_CREATION_DATE_TIME = 701;
    public static final int KM_TAG_ORIGIN = 702;
    public static final int KM_ORIGIN_GENERATED = 0;
    public static final int KM_PURPOSE_SIGN = 2;

    // ~ Instance fields
    // ================================================================================================

    private final Logger logger = LoggerFactory.getLogger(KeyDescriptionVerifier.class);

    public void verify(@NotNull X509Certificate x509Certificate, @NotNull byte[] clientDataHash, boolean teeEnforcedOnly) {
        AssertUtil.notNull(x509Certificate, "x509Certificate must not be null");
        AssertUtil.notNull(clientDataHash, "clientDataHash must not be null");

        try {
            Asn1Container keyDescription = extractKeyDescription(x509Certificate);
            doVerify(keyDescription, clientDataHash, teeEnforcedOnly);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @NotNull Asn1Container extractKeyDescription(@NotNull X509Certificate x509Certificate) throws IOException {

        byte[] attestationExtensionBytes = x509Certificate.getExtensionValue(ATTESTATION_EXTENSION_OID);
        Asn1OctetString envelope = new Asn1OctetString();
        if (attestationExtensionBytes == null) {
            throw new KeyDescriptionValidationException("KeyDescription must not be null");
        }
        envelope.decode(attestationExtensionBytes);
        return (Asn1Container) Asn1Parser.parse(ByteBuffer.wrap(envelope.getValue()));
    }

    void doVerify(@NotNull Asn1Container keyDescription, @NotNull byte[] clientDataHash, boolean teeEnforcedOnly) throws IOException {
        /// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        byte[] attestationChallenge = keyDescription.getChildren().get(ATTESTATION_CHALLENGE_INDEX).readBodyBytes();
        // As attestationChallenge is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(attestationChallenge, clientDataHash)) {
            throw new KeyDescriptionValidationException("Attestation challenge doesn't match.");
        }

        /// Verify the following using the appropriate authorization list from the attestation certificate extension data:

        /// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        Asn1Container softwareEnforced = (Asn1Container) keyDescription.getChildren().get(SW_ENFORCED_INDEX);
        Asn1Container teeEnforced = (Asn1Container) keyDescription.getChildren().get(TEE_ENFORCED_INDEX);

        if (findAuthorizationListEntry(softwareEnforced, KM_TAG_ALL_APPLICATIONS) != null ||
                findAuthorizationListEntry(teeEnforced, KM_TAG_ALL_APPLICATIONS) != null) {
            throw new KeyDescriptionValidationException("Key is not scoped properly.");
        }

        verifyAuthorizationList(teeEnforcedOnly, softwareEnforced, teeEnforced);
    }

    private void verifyAuthorizationList(boolean teeEnforcedOnly, @NotNull Asn1Container softwareEnforced, @NotNull Asn1Container teeEnforced) throws IOException {
        /// For the following,
        /// use only the teeEnforced authorization list if the RP wants to accept only keys
        /// from a trusted execution environment,
        if (teeEnforcedOnly) {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if (!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN))) {
                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if (!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE))) {
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
        /// otherwise use the union of teeEnforced and softwareEnforced.
        else {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if (!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN)) &&
                    !isKeyGeneratedInKeymaster(findAuthorizationListEntry(softwareEnforced, KM_TAG_ORIGIN))) {

                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if (!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE)) &&
                    !containsValidPurpose(findAuthorizationListEntry(softwareEnforced, KM_TAG_PURPOSE))) {
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean isKeyGeneratedInKeymaster(@Nullable Asn1ParseResult origin) {
        try {
            return Objects.equals(getIntegerFromAsn1(origin), BigInteger.valueOf(KM_ORIGIN_GENERATED));
        } catch (RuntimeException | IOException e) {
            logger.debug("Failed to retrieve origin.", e);
            return false;
        }
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean containsValidPurpose(@Nullable Asn1ParseResult purposes) throws IOException {
        try {
            if (purposes == null) {
                return false;
            }
            Asn1Container set = (Asn1Container) purposes;
            for (Asn1ParseResult purpose : set.getChildren()) {
                if (Objects.equals(getIntegerFromAsn1(purpose), BigInteger.valueOf(KM_PURPOSE_SIGN))) {
                    return true;
                }
            }
            return false;
        } catch (RuntimeException e) {
            logger.debug("Failed to retrieve purpose.", e);
            return false;
        }
    }


    private @Nullable BigInteger getIntegerFromAsn1(Asn1ParseResult asn1Value) throws IOException {
        if (asn1Value == null) {
            return null;
        }
        if (!asn1Value.isPrimitive()) {
            throw new BadAttestationStatementException(String.format("ASN1Integer is expected. Found %s instead.", asn1Value.getClass().getName()));
        }
        Asn1Integer value = new Asn1Integer();
        value.decode(asn1Value);
        return value.getValue();
    }

    private @Nullable Asn1ParseResult findAuthorizationListEntry(
            @NotNull Asn1Container authorizationList, int tag) {
        for (Asn1ParseResult entry : authorizationList.getChildren()) {
            if (entry.tagNo() == tag) {
                return ((Asn1Container) entry).getChildren().get(0);
            }
        }
        return null;
    }


}
