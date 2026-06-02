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

package com.webauthn4j.metadata.converter.jackson;

import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardClearingMixin;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.AAIDDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.AuthenticatorStatusDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataAAGUIDRelaxedDeserializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AAIDSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AuthenticatorStatusSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.MetadataAAGUIDSerializer;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.uaf.AAID;
import tools.jackson.databind.module.SimpleModule;

public class WebAuthnMetadataJSONModule extends SimpleModule {

    @SuppressWarnings("deprecation")
    public WebAuthnMetadataJSONModule() {
        super("WebAuthnMetadataJSONModule");

        this.addSerializer(AAGUID.class, new MetadataAAGUIDSerializer());
        this.addDeserializer(AAGUID.class, new MetadataAAGUIDRelaxedDeserializer());

        // These types have @JsonSerialize/@JsonDeserialize guard annotations that are cleared by setupModule() via MixIn.
        this.addSerializer(AAID.class, new AAIDSerializer());
        this.addDeserializer(AAID.class, new AAIDDeserializer());
        this.addSerializer(AuthenticatorStatus.class, new AuthenticatorStatusSerializer());
        this.addDeserializer(AuthenticatorStatus.class, new AuthenticatorStatusDeserializer());
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
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AAID.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AuthenticatorStatus.class);
    }

}
