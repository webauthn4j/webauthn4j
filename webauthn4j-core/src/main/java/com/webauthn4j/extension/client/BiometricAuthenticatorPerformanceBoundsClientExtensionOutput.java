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
import java.util.Objects;

public class BiometricAuthenticatorPerformanceBoundsClientExtensionOutput extends AbstractClientExtensionOutput<BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.AuthenticatorBiometricPerfBounds> {

    public static final String ID = "biometricPerfBounds";

    @JsonCreator
    public BiometricAuthenticatorPerformanceBoundsClientExtensionOutput(AuthenticatorBiometricPerfBounds value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    public static class AuthenticatorBiometricPerfBounds implements Serializable {

        @SuppressWarnings("squid:S00116")
        private float FAR;
        @SuppressWarnings("squid:S00116")
        private float FRR;

        public AuthenticatorBiometricPerfBounds(
                @SuppressWarnings("squid:S00117") float FAR,
                @SuppressWarnings("squid:S00117") float FRR) {
            this.FAR = FAR;
            this.FRR = FRR;
        }

        public AuthenticatorBiometricPerfBounds() {
        }

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
