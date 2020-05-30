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

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.converter.jackson.serializer.*;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.authenticator.*;
import com.webauthn4j.data.jws.JWS;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn CBOR data structures
 */
public class WebAuthnCBORModule extends SimpleModule {

    public WebAuthnCBORModule(ObjectConverter objectConverter) {
        super("WebAuthnCBORModule");

        this.addDeserializer(AAGUID.class, new AAGUIDDeserializer());
        this.addDeserializer(AttestedCredentialData.class, new AttestedCredentialDataDeserializer(objectConverter));
        this.addDeserializer(AuthenticationExtensionsAuthenticatorOutputsEnvelope.class, new AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer());
        this.addDeserializer(CertPath.class, new CertPathDeserializer());
        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(COSEKeyEnvelope.class, new COSEKeyEnvelopeDeserializer());
        this.addDeserializer(AuthenticatorData.class, new AuthenticatorDataDeserializer(objectConverter));
        this.addDeserializer(ExtensionAuthenticatorOutput.class, new ExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(UnknownExtensionAuthenticatorOutput.class, new UnknownExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(TPMSAttest.class, new TPMSAttestDeserializer());
        this.addDeserializer(TPMTPublic.class, new TPMTPublicDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(objectConverter));

        this.addSerializer(new AAGUIDSerializer());
        this.addSerializer(new AttestedCredentialDataSerializer(objectConverter));
        this.addSerializer(new AuthenticatorDataSerializer(objectConverter));
        this.addSerializer(new CertPathSerializer());
        this.addSerializer(new ChallengeSerializer());
        this.addSerializer(new EC2COSEKeySerializer());
        this.addSerializer(new JWSSerializer());
        this.addSerializer(new OriginSerializer());
        this.addSerializer(new RSACOSEKeySerializer());
        this.addSerializer(new TPMSAttestSerializer());
        this.addSerializer(new TPMTPublicSerializer());
        this.addSerializer(new X509CertificateSerializer());

        // attestation statements
        this.registerSubtypes(new NamedType(FIDOU2FAttestationStatement.class, FIDOU2FAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(PackedAttestationStatement.class, PackedAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidKeyAttestationStatement.class, AndroidKeyAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidSafetyNetAttestationStatement.class, AndroidSafetyNetAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(TPMAttestationStatement.class, TPMAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(NoneAttestationStatement.class, NoneAttestationStatement.FORMAT));

        // authenticator extension outputs

    }

}
