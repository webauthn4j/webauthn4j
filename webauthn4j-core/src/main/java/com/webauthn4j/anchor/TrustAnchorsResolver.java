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

package com.webauthn4j.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Core interface that resolves {@link TrustAnchor} {@link Set} from {@link AAGUID}.
 * @deprecated
 */
@Deprecated
public interface TrustAnchorsResolver {

    /**
     * Resolves {@link TrustAnchor} {@link Set} from {@link AAGUID}.
     *
     * @param aaguid {@link AAGUID} for authenticator
     * @return {@link TrustAnchor} {@link Set}.
     */
    @NonNull Set<TrustAnchor> resolve(@NonNull AAGUID aaguid);
}
