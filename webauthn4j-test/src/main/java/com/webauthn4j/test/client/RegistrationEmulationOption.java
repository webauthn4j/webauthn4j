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

package com.webauthn4j.test.client;

import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.TestUtil;

public class RegistrationEmulationOption {

    private boolean signatureOverrideEnabled = false;
    private byte[] signature = new byte[]{0x01, 0x23, 0x45, 0x67};
    private boolean collectedClientDataOverrideEnabled = false;
    private CollectedClientData collectedClientData = TestUtil.createClientData(ClientDataType.CREATE);

    public boolean isSignatureOverrideEnabled() {
        return signatureOverrideEnabled;
    }

    public void setSignatureOverrideEnabled(boolean signatureOverrideEnabled) {
        this.signatureOverrideEnabled = signatureOverrideEnabled;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public boolean isCollectedClientDataOverrideEnabled() {
        return collectedClientDataOverrideEnabled;
    }

    public void setCollectedClientDataOverrideEnabled(boolean collectedClientDataOverrideEnabled) {
        this.collectedClientDataOverrideEnabled = collectedClientDataOverrideEnabled;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public void setCollectedClientData(CollectedClientData collectedClientData) {
        this.collectedClientData = collectedClientData;
    }
}
