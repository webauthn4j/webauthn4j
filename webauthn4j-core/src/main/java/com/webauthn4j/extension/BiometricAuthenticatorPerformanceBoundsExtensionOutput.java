package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Objects;

public class BiometricAuthenticatorPerformanceBoundsExtensionOutput extends AbstractExtensionOutput<BiometricAuthenticatorPerformanceBoundsExtensionOutput.AuthenticatorBiometricPerfBounds> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("biometricPerfBounds");

    @JsonCreator
    public BiometricAuthenticatorPerformanceBoundsExtensionOutput(AuthenticatorBiometricPerfBounds value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

    public static class AuthenticatorBiometricPerfBounds{

        private float FAR;
        private float FRR;

        public AuthenticatorBiometricPerfBounds(float FAR, float FRR) {
            this.FAR = FAR;
            this.FRR = FRR;
        }

        public AuthenticatorBiometricPerfBounds(){}

        public float getFAR() {
            return FAR;
        }

        public float getFRR() {
            return FRR;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthenticatorBiometricPerfBounds that = (AuthenticatorBiometricPerfBounds) o;
            return Float.compare(that.FAR, FAR) == 0 &&
                    Float.compare(that.FRR, FRR) == 0;
        }

        @Override
        public int hashCode() {

            return Objects.hash(FAR, FRR);
        }
    }

}
