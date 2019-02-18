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

package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.converter.jackson.serializer.ChallengeSerializer;
import com.webauthn4j.converter.jackson.serializer.JWSSerializer;
import com.webauthn4j.converter.jackson.serializer.X509CertificateSerializer;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.request.extension.client.ExtensionClientInput;
import com.webauthn4j.request.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.request.extension.client.SupportedExtensionsExtensionClientInput;
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.extension.client.*;
import com.webauthn4j.util.jws.JWS;

import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn classes serialization and deserialization
 */
public class WebAuthnJSONModule extends SimpleModule {

    public WebAuthnJSONModule(JsonConverter jsonConverter, CborConverter cborConverter) {
        super("WebAuthnJSONModule");

        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(ExtensionClientInput.class, new ExtensionClientInputDeserializer());
        this.addDeserializer(ExtensionClientOutput.class, new ExtensionClientOutputDeserializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(jsonConverter));
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(Challenge.class, new ChallengeSerializer());
        this.addSerializer(JWS.class, new JWSSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        this.registerSubtypes(new NamedType(FIDOU2FAttestationStatement.class, FIDOU2FAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(PackedAttestationStatement.class, PackedAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidKeyAttestationStatement.class, AndroidKeyAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidSafetyNetAttestationStatement.class, AndroidSafetyNetAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(TPMAttestationStatement.class, TPMAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(NoneAttestationStatement.class, NoneAttestationStatement.FORMAT));


        this.registerSubtypes(new NamedType(FIDOAppIDExtensionClientInput.class, FIDOAppIDExtensionClientInput.ID));
        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionClientInput.class, SupportedExtensionsExtensionClientInput.ID));

        this.registerSubtypes(new NamedType(AuthenticatorSelectionExtensionClientOutput.class, AuthenticatorSelectionExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.class, BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(FIDOAppIDExtensionClientOutput.class, FIDOAppIDExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(GenericTransactionAuthorizationExtensionClientOutput.class, GenericTransactionAuthorizationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(LocationExtensionClientOutput.class, LocationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(SimpleTransactionAuthorizationExtensionClientOutput.class, SimpleTransactionAuthorizationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionClientOutput.class, SupportedExtensionsExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(UserVerificationIndexExtensionClientOutput.class, UserVerificationIndexExtensionClientOutput.ID));

    }

}
