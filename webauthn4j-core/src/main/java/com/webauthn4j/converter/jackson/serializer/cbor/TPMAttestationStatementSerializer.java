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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.statement.TPMAttestationStatement;

import java.util.Arrays;

public class TPMAttestationStatementSerializer extends AbstractCtapCanonicalCborSerializer<TPMAttestationStatement> {

    public TPMAttestationStatementSerializer() {
        super(TPMAttestationStatement.class, Arrays.asList(
                // CTAP2 canonical CBOR order: string keys sorted by length ascending,
                // then lexicographically by encoded bytes (for same-length keys only).
                // For 3-byte keys: "ver" (0x766572) comes before "x5c" (0x783563) since 0x76 < 0x78.
                // For different lengths: "pubArea" (7 bytes) comes before "certInfo" (8 bytes).
                new FieldSerializationRule<>("alg", TPMAttestationStatement::getAlg),
                new FieldSerializationRule<>("sig", TPMAttestationStatement::getSig),
                new FieldSerializationRule<>("ver", TPMAttestationStatement::getVer),
                new FieldSerializationRule<>("x5c", TPMAttestationStatement::getX5c),
                new FieldSerializationRule<>("pubArea", TPMAttestationStatement::getPubArea),
                new FieldSerializationRule<>("certInfo", TPMAttestationStatement::getCertInfo)
        ));
    }
}
