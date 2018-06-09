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
