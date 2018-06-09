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

package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

public class GenericTransactionAuthorizationClientExtensionOutput extends AbstractClientExtensionOutput<GenericTransactionAuthorizationClientExtensionOutput.TxAuthnGenericArg> {

    public static final String ID = "txAuthGeneric";

    @JsonCreator
    public GenericTransactionAuthorizationClientExtensionOutput(TxAuthnGenericArg value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    public static class TxAuthnGenericArg implements Serializable {

        private String contentType;
        private byte[] content;

        public TxAuthnGenericArg(String contentType, byte[] content) {
            this.contentType = contentType;
            this.content = content;
        }

        public TxAuthnGenericArg() {
        }

        public String getContentType() {
            return contentType;
        }

        public byte[] getContent() {
            return content;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TxAuthnGenericArg that = (TxAuthnGenericArg) o;
            return Objects.equals(contentType, that.contentType) &&
                    Arrays.equals(content, that.content);
        }

        @Override
        public int hashCode() {

            int result = Objects.hash(contentType);
            result = 31 * result + Arrays.hashCode(content);
            return result;
        }
    }

}
