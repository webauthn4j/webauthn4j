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

package com.webauthn4j.metadata.legacy.data.statement;

import com.webauthn4j.data.TransactionConfirmationDisplay;
import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class TransactionConfirmationDisplays extends AbstractSet<TransactionConfirmationDisplay> {

    private final Set<TransactionConfirmationDisplay> transactionConfirmationDisplays;

    public TransactionConfirmationDisplays(int value) {
        Set<TransactionConfirmationDisplay> set = new HashSet<>();
        if ((value & TransactionConfirmationDisplay.ANY.getValue()) > 0) {
            set.add(TransactionConfirmationDisplay.ANY);
        }
        if ((value & TransactionConfirmationDisplay.PRIVILEGED_SOFTWARE.getValue()) > 0) {
            set.add(TransactionConfirmationDisplay.PRIVILEGED_SOFTWARE);
        }
        if ((value & TransactionConfirmationDisplay.TEE.getValue()) > 0) {
            set.add(TransactionConfirmationDisplay.TEE);
        }
        if ((value & TransactionConfirmationDisplay.HARDWARE.getValue()) > 0) {
            set.add(TransactionConfirmationDisplay.HARDWARE);
        }
        if ((value & TransactionConfirmationDisplay.REMOTE.getValue()) > 0) {
            set.add(TransactionConfirmationDisplay.REMOTE);
        }
        transactionConfirmationDisplays = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<TransactionConfirmationDisplay> iterator() {
        return transactionConfirmationDisplays.iterator();
    }

    @Override
    public int size() {
        return transactionConfirmationDisplays.size();
    }
}
