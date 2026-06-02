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

import com.webauthn4j.converter.jackson.deserializer.cbor.*;
import com.webauthn4j.converter.jackson.serializer.cbor.*;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.data.extension.authenticator.*;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.jsontype.NamedType;
import tools.jackson.databind.module.SimpleModule;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn CBOR data structures
 */
public class WebAuthnCBORModule extends SimpleModule {

    public WebAuthnCBORModule(@NotNull ObjectConverter objectConverter) {
        super("WebAuthnCBORModule");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        // Guarded types: these have @JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class) /
        // @JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class) annotations.
        // The guard annotations are cleared by setupModule() via MixIn so that these serializers/deserializers take effect.
        this.addSerializer(new AuthenticatorTransportSerializer());
        this.addDeserializer(AuthenticatorTransport.class, new AuthenticatorTransportDeserializer());
        this.addSerializer(new COSEAlgorithmIdentifierSerializer());
        this.addDeserializer(COSEAlgorithmIdentifier.class, new COSEAlgorithmIdentifierDeserializer());
        this.addSerializer(new COSEKeyOperationSerializer());
        this.addDeserializer(COSEKeyOperation.class, new COSEKeyOperationDeserializer());
        this.addSerializer(new COSEKeyTypeSerializer());
        this.addDeserializer(COSEKeyType.class, new COSEKeyTypeDeserializer());
        this.addSerializer(new CurveSerializer());
        this.addDeserializer(Curve.class, new CurveDeserializer());

        // Non-guarded types
        this.addSerializer(new AAGUIDSerializer());
        this.addDeserializer(AAGUID.class, new AAGUIDDeserializer());
        this.addSerializer(new AttestationObjectSerializer());
        this.addSerializer(new AndroidKeyAttestationStatementSerializer());
        this.addSerializer(new AndroidSafetyNetAttestationStatementSerializer());
        this.addSerializer(new AppleAnonymousAttestationStatementSerializer());
        this.addSerializer(new NoneAttestationStatementSerializer());
        this.addSerializer(new AttestedCredentialDataSerializer(objectConverter));
        this.addDeserializer(AttestedCredentialData.class, new AttestedCredentialDataDeserializer(objectConverter));
        this.addSerializer(new AuthenticatorDataSerializer(objectConverter));
        this.addDeserializer(AuthenticatorData.class, new AuthenticatorDataDeserializer(objectConverter));
        this.addSerializer(new CertPathSerializer());
        this.addDeserializer(CertPath.class, new CertPathDeserializer());
        this.addSerializer(new CredentialProtectionPolicySerializer());
        this.addDeserializer(CredentialProtectionPolicy.class, new CredentialProtectionPolicyDeserializer());
        this.addSerializer(new EC2COSEKeySerializer());
        this.addSerializer(new EdDSACOSEKeySerializer());
        this.addDeserializer(COSEKeyEnvelope.class, new COSEKeyEnvelopeDeserializer());
        this.addSerializer(new FIDOU2FAttestationStatementSerializer());
        this.addSerializer(new HMACGetSecretAuthenticatorInputSerializer());
        this.addSerializer(new JWSSerializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(objectConverter));
        this.addSerializer(new PackedAttestationStatementSerializer());
        this.addSerializer(new PublicKeyCredentialDescriptorSerializer());
        this.addSerializer(new RSACOSEKeySerializer());
        this.addSerializer(new TPMAttestationStatementSerializer());
        this.addSerializer(new TPMSAttestSerializer());
        this.addDeserializer(TPMSAttest.class, new TPMSAttestDeserializer());
        this.addSerializer(new TPMTPublicSerializer());
        this.addDeserializer(TPMTPublic.class, new TPMTPublicDeserializer());
        this.addSerializer(new X509CertificateSerializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());
        this.addDeserializer(AuthenticationExtensionsAuthenticatorOutputsEnvelope.class, new AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer());
        this.addSerializer(new AuthenticationExtensionsAuthenticatorInputsSerializer());
        this.addSerializer(new AuthenticationExtensionsAuthenticatorOutputsSerializer());

        // Attestation statement subtypes
        this.registerSubtypes(new NamedType(FIDOU2FAttestationStatement.class, FIDOU2FAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(PackedAttestationStatement.class, PackedAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidKeyAttestationStatement.class, AndroidKeyAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidSafetyNetAttestationStatement.class, AndroidSafetyNetAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(TPMAttestationStatement.class, TPMAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AppleAnonymousAttestationStatement.class, AppleAnonymousAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(NoneAttestationStatement.class, NoneAttestationStatement.FORMAT));

        // Authenticator extension output deserializers
        this.addDeserializer(UserVerificationMethodExtensionAuthenticatorOutput.class, new UserVerificationMethodExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(CredentialProtectionExtensionAuthenticatorOutput.class, new CredentialProtectionExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(HMACSecretRegistrationExtensionAuthenticatorOutput.class, new HMACSecretRegistrationExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(HMACSecretAuthenticationExtensionAuthenticatorOutput.class, new HMACSecretAuthenticationExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(AuthenticationExtensionsAuthenticatorOutputs.class, new AuthenticationExtensionsAuthenticatorOutputsDeserializer(objectConverter));

        // Authenticator extension input deserializers
        this.addDeserializer(UserVerificationMethodExtensionAuthenticatorInput.class, new UserVerificationMethodExtensionAuthenticatorInputDeserializer());
        this.addDeserializer(CredentialProtectionExtensionAuthenticatorInput.class, new CredentialProtectionExtensionAuthenticatorInputDeserializer());
        this.addDeserializer(HMACSecretRegistrationExtensionAuthenticatorInput.class, new HMACSecretRegistrationExtensionAuthenticatorInputDeserializer());
        this.addDeserializer(HMACSecretAuthenticationExtensionAuthenticatorInput.class, new HMACSecretAuthenticationExtensionAuthenticatorInputDeserializer());
        this.addDeserializer(AuthenticationExtensionsAuthenticatorInputs.class, new AuthenticationExtensionsAuthenticatorInputsDeserializer(objectConverter));

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
    }

}
