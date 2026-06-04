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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.data.AbstractImmutableMap;
import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.Map;

/**
 * Represents a map of friendly names for an authenticator, keyed by language tag.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-rd-20251016.html#dictdef-friendlynames">FriendlyNames in Metadata Statement v3.1.1</a>
 */
public class FriendlyNames extends AbstractImmutableMap<String, String> {

    @JsonCreator
    public FriendlyNames(@NotNull Map<String, String> map) {
        super(map);
    }

    public FriendlyNames() {
        this(Collections.emptyMap());
    }
}
