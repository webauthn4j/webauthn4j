package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Arrays;
import java.util.Objects;

public class GenericTransactionAuthorizationExtensionOutput extends AbstractExtensionOutput<GenericTransactionAuthorizationExtensionOutput.TxAuthnGenericArg> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("txAuthGeneric");

    @JsonCreator
    public GenericTransactionAuthorizationExtensionOutput(TxAuthnGenericArg value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

    public static class TxAuthnGenericArg {

        private String contentType;
        private byte[] content;

        public TxAuthnGenericArg(String contentType, byte[] content) {
            this.contentType = contentType;
            this.content = content;
        }

        public TxAuthnGenericArg(){}

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
