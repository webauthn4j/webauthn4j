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

package com.webauthn4j.metadata.legacy.validator;

import com.webauthn4j.metadata.exception.UnknownProtocolFamilyException;
import com.webauthn4j.metadata.legacy.data.statement.MetadataStatement;

import java.util.Arrays;
import java.util.List;

@Deprecated
public class MetadataStatementValidator {

    private final List<String> KNOWN_PROTOCOL_FAMILY = Arrays.asList("uaf", "u2f", "fido2");
    private final List<String> KNOWN_ASSERTION_SCHEME = Arrays.asList("FIDOV2", "U2FV1BIN", "UAFV1TLV");

    public void validate(MetadataStatement metadataStatement) {
        validateProtocolFamily(metadataStatement.getProtocolFamily());
        validateAssertionScheme(metadataStatement.getAssertionScheme());
    }

    private void validateProtocolFamily(String protocolFamily) {
        if (!KNOWN_PROTOCOL_FAMILY.contains(protocolFamily)) {
            throw new UnknownProtocolFamilyException(String.format("Unknown protocol family '%s' is provided", protocolFamily));
        }
    }

    private void validateAssertionScheme(String assertionScheme) {
        if (!KNOWN_ASSERTION_SCHEME.contains(assertionScheme)) {
            throw new UnknownProtocolFamilyException(String.format("Unknown assertion scheme '%s' is provided", assertionScheme));
        }
    }
}
