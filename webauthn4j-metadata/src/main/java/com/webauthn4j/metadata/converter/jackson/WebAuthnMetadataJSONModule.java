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

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.metadata.converter.jackson.deserializer.AttachmentHintsDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.KeyProtectionsDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.MatcherProtectionsDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.TransactionConfirmationDisplaysDeserializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AttachmentHintsSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.KeyProtectionsSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.MatcherProtectionsSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.TransactionConfirmationDisplaysSerializer;
import com.webauthn4j.data.statement.AttachmentHints;
import com.webauthn4j.data.statement.KeyProtections;
import com.webauthn4j.data.statement.MatcherProtections;
import com.webauthn4j.data.statement.TransactionConfirmationDisplays;

public class WebAuthnMetadataJSONModule extends SimpleModule {

    public WebAuthnMetadataJSONModule() {
        super("WebAuthnMetadataJSONModule");

        this.addDeserializer(AttachmentHints.class, new AttachmentHintsDeserializer());
        this.addDeserializer(KeyProtections.class, new KeyProtectionsDeserializer());
        this.addDeserializer(MatcherProtections.class, new MatcherProtectionsDeserializer());
        this.addDeserializer(TransactionConfirmationDisplays.class, new TransactionConfirmationDisplaysDeserializer());

        this.addSerializer(AttachmentHints.class, new AttachmentHintsSerializer());
        this.addSerializer(KeyProtections.class, new KeyProtectionsSerializer());
        this.addSerializer(MatcherProtections.class, new MatcherProtectionsSerializer());
        this.addSerializer(TransactionConfirmationDisplays.class, new TransactionConfirmationDisplaysSerializer());

    }

}
