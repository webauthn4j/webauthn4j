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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.Base64UrlUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;

/**
 * Jackson Serializer for {@link Challenge}
 */
public class ChallengeSerializer extends StdSerializer<Challenge> {

    public ChallengeSerializer() {
        super(Challenge.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void serialize(@NonNull Challenge value, @NonNull JsonGenerator gen, @NonNull SerializerProvider provider) throws IOException {
        String challenge = Base64UrlUtil.encodeToString(value.getValue());
        gen.writeString(challenge);
    }
}
