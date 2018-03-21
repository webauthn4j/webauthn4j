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

package com.webauthn4j.webauthn.attestation.authenticator;

public class CoseAlgorithmConst {

    private CoseAlgorithmConst(){}

    public static final int RS256 = -257;
    public static final int RS384 = -258;
    public static final int RS512 = -259;
    public static final int ED256 = -260;
    public static final int ED512 = -261;
    public static final int RS1 = -262;

    public static final int ES256 = -7;
    public static final int ES384 = -35;
    public static final int ES512 = -36;

    public static final int PS256 = -37;
    public static final int PS384 = -38;
    public static final int PS512 = -39;
}
