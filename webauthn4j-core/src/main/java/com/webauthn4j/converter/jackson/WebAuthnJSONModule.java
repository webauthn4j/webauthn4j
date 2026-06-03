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

package com.webauthn4j.converter.jackson;

import com.webauthn4j.converter.jackson.deserializer.json.*;
import com.webauthn4j.converter.jackson.serializer.json.*;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.client.*;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.module.SimpleModule;

import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn JSON data structures
 */
public class WebAuthnJSONModule extends SimpleModule {

    @SuppressWarnings("unused")
    public WebAuthnJSONModule(@NotNull ObjectConverter objectConverter) {
        super("WebAuthnJSONModule");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.addDeserializer(AttachmentHint.class, new AttachmentHintFromLongDeserializer());
        this.addDeserializer(AuthenticatorAttestationType.class, new AuthenticatorAttestationTypeFromIntDeserializer());
        this.addDeserializer(AuthenticationAlgorithm.class, new AuthenticationAlgorithmFromIntDeserializer());
        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(CredentialProtectionPolicy.class, new CredentialProtectionPolicyDeserializer());
        this.addDeserializer(JWSHeader.class, new JWSHeaderDeserializer());
        this.addDeserializer(KeyProtectionType.class, new KeyProtectionTypeFromIntDeserializer());
        this.addDeserializer(MatcherProtectionType.class, new MatcherProtectionTypeFromIntDeserializer());
        this.addDeserializer(PublicKeyRepresentationFormat.class, new PublicKeyRepresentationFormatFromIntDeserializer());
        this.addDeserializer(TransactionConfirmationDisplay.class, new TransactionConfirmationDisplayFromIntDeserializer());
        this.addDeserializer(UserVerificationMethod.class, new UserVerificationMethodFromLongDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        // These types have @JsonSerialize/@JsonDeserialize guard annotations that are cleared by setupModule() via MixIn.
        this.addDeserializer(AuthenticatorTransport.class, new AuthenticatorTransportDeserializer());
        this.addDeserializer(COSEAlgorithmIdentifier.class, new COSEAlgorithmIdentifierDeserializer());
        this.addDeserializer(COSEKeyOperation.class, new COSEKeyOperationDeserializer());
        this.addDeserializer(COSEKeyType.class, new COSEKeyTypeDeserializer());
        this.addDeserializer(Curve.class, new CurveDeserializer());
        this.addDeserializer(JWAIdentifier.class, new JWAIdentifierDeserializer());
        this.addDeserializer(MessageDigestAlgorithm.class, new MessageDigestAlgorithmDeserializer());
        this.addDeserializer(Origin.class, new OriginDeserializer());
        this.addDeserializer(SignatureAlgorithm.class, new SignatureAlgorithmDeserializer());
        this.addDeserializer(TPMEccCurve.class, new TPMEccCurveDeserializer());
        this.addDeserializer(TPMGenerated.class, new TPMGeneratedDeserializer());
        this.addDeserializer(TPMIAlgHash.class, new TPMIAlgHashDeserializer());
        this.addDeserializer(TPMIAlgPublic.class, new TPMIAlgPublicDeserializer());
        this.addDeserializer(TPMISTAttest.class, new TPMISTAttestDeserializer());

        this.addDeserializer(byte[].class, new ByteArrayBase64UrlDeserializer());

        this.addDeserializer(AuthenticationExtensionsClientOutputs.class, new AuthenticationExtensionsClientOutputsDeserializer(objectConverter));

        this.addDeserializer(AuthenticationExtensionsClientInputs.class, new AuthenticationExtensionsClientInputsDeserializer(objectConverter));

        // Extension input deserializers
        this.addDeserializer(FIDOAppIDExtensionClientInput.class, new FIDOAppIDExtensionClientInputDeserializer());
        this.addDeserializer(FIDOAppIDExclusionExtensionClientInput.class, new FIDOAppIDExclusionExtensionClientInputDeserializer());
        this.addDeserializer(UserVerificationMethodExtensionClientInput.class, new UserVerificationMethodExtensionClientInputDeserializer());
        this.addDeserializer(CredentialPropertiesExtensionClientInput.class, new CredentialPropertiesExtensionClientInputDeserializer());
        this.addDeserializer(CredentialProtectionExtensionClientInput.class, new CredentialProtectionExtensionClientInputDeserializer());
        this.addDeserializer(HMACSecretRegistrationExtensionClientInput.class, new HMACSecretRegistrationExtensionClientInputDeserializer());
        this.addDeserializer(HMACSecretAuthenticationExtensionClientInput.class, new HMACSecretAuthenticationExtensionClientInputDeserializer());

        // Extension output deserializers
        this.addDeserializer(FIDOAppIDExtensionClientOutput.class, new FIDOAppIDExtensionClientOutputDeserializer());
        this.addDeserializer(FIDOAppIDExclusionExtensionClientOutput.class, new FIDOAppIDExclusionExtensionClientOutputDeserializer());
        this.addDeserializer(UserVerificationMethodExtensionClientOutput.class, new UserVerificationMethodExtensionClientOutputDeserializer());
        this.addDeserializer(CredentialPropertiesExtensionClientOutput.class, new CredentialPropertiesExtensionClientOutputDeserializer());
        this.addDeserializer(HMACSecretRegistrationExtensionClientOutput.class, new HMACSecretRegistrationExtensionClientOutputDeserializer());
        this.addDeserializer(HMACSecretAuthenticationExtensionClientOutput.class, new HMACSecretAuthenticationExtensionClientOutputDeserializer());

        this.addSerializer(AttachmentHint.class, new AttachmentHintToLongSerializer());
        this.addSerializer(AuthenticatorAttestationType.class, new AuthenticatorAttestationTypeToIntSerializer());
        this.addSerializer(AuthenticationAlgorithm.class, new AuthenticationAlgorithmToIntSerializer());
        this.addSerializer(new ChallengeSerializer());
        this.addSerializer(new CredentialProtectionPolicySerializer());
        this.addSerializer(new JWSHeaderSerializer());
        this.addSerializer(new KeyProtectionTypeToIntSerializer());
        this.addSerializer(new MatcherProtectionTypeToIntSerializer());
        this.addSerializer(new OriginSerializer());
        this.addSerializer(PublicKeyRepresentationFormat.class, new PublicKeyRepresentationFormatToIntSerializer());
        this.addSerializer(TransactionConfirmationDisplay.class, new TransactionConfirmationDisplayToIntSerializer());
        this.addSerializer(UserVerificationMethod.class, new UserVerificationMethodToLongSerializer());
        this.addSerializer(new X509CertificateSerializer());

        this.addSerializer(new AuthenticatorTransportSerializer());
        this.addSerializer(new COSEAlgorithmIdentifierSerializer());
        this.addSerializer(new COSEKeyOperationSerializer());
        this.addSerializer(new COSEKeyTypeSerializer());
        this.addSerializer(new CurveSerializer());
        this.addSerializer(new JWAIdentifierSerializer());
        this.addSerializer(new MessageDigestAlgorithmSerializer());
        this.addSerializer(new SignatureAlgorithmSerializer());
        this.addSerializer(new TPMEccCurveSerializer());
        this.addSerializer(new TPMGeneratedSerializer());
        this.addSerializer(new TPMIAlgHashSerializer());
        this.addSerializer(new TPMIAlgPublicSerializer());
        this.addSerializer(new TPMISTAttestSerializer());

        this.addSerializer(new ByteArrayBase64UrlSerializer());

    }

    @Override
    public void setupModule(SetupContext context) {
        super.setupModule(context);
        // These classes have @JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class) /
        // @JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class) annotations that throw
        // if no module is registered. Clear them so that the serializers/deserializers registered above
        // via addSerializer/addDeserializer take effect instead.
        // This is necessary because Jackson resolves annotation-based serializers before module-registered ones.
        // Only set the clearing MixIn if the user hasn't already provided their own MixIn for the type.
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AuthenticatorTransport.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, COSEAlgorithmIdentifier.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, COSEKeyOperation.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, COSEKeyType.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, Curve.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, JWAIdentifier.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, MessageDigestAlgorithm.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, Origin.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, SignatureAlgorithm.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, TPMEccCurve.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, TPMGenerated.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, TPMIAlgHash.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, TPMIAlgPublic.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, TPMISTAttest.class);
    }

}
