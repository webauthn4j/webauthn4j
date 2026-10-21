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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs">
 * §10.1.4. Pseudo-random function extension (prf)</a>
 */
public class AuthenticationExtensionsPRFOutputs {

    private final Boolean enabled;
    private final AuthenticationExtensionsPRFValues results;

    @JsonCreator
    public AuthenticationExtensionsPRFOutputs(
            @Nullable @JsonProperty("enabled") Boolean enabled,
            @Nullable @JsonProperty("results") AuthenticationExtensionsPRFValues results) {
        this.enabled = enabled;
        this.results = results;
    }

    public @Nullable Boolean getEnabled() {
        return enabled;
    }

    public @Nullable AuthenticationExtensionsPRFValues getResults() {
        return results;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsPRFOutputs that = (AuthenticationExtensionsPRFOutputs) o;
        return Objects.equals(enabled, that.enabled) && Objects.equals(results, that.results);
    }

    @Override
    public int hashCode() {
        return Objects.hash(enabled, results);
    }
}
