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

package com.webauthn4j.appattest.converter;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

/**
 * {@link AuthenticatorDataConverter} for Apple App Attest assertions.
 *
 * Handles Apple-specific deviation from the WebAuthn spec:
 * AT flag set without attested credential data (assertion flow).
 */
public class DCAssertionAuthenticatorDataConverter extends AuthenticatorDataConverter {

    public DCAssertionAuthenticatorDataConverter(@NotNull ObjectConverter objectConverter) {
        super(objectConverter);
    }

    @Override
    protected @Nullable AttestedCredentialData parseAttestedCredentialData(byte flags, @NotNull ByteBuffer byteBuffer) {
        // App Attest assertions never contain attested credential data, even when AT is set.
        return null;
    }

}
