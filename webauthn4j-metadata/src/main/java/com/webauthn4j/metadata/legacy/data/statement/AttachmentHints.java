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

import com.webauthn4j.data.AttachmentHint;
import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

@Deprecated
public class AttachmentHints extends AbstractSet<AttachmentHint> {

    private final Set<AttachmentHint> attachmentHints;

    public AttachmentHints(long value) {
        Set<AttachmentHint> set = new HashSet<>();
        if ((value & AttachmentHint.INTERNAL.getValue()) > 0) {
            set.add(AttachmentHint.INTERNAL);
        }
        if ((value & AttachmentHint.EXTERNAL.getValue()) > 0) {
            set.add(AttachmentHint.EXTERNAL);
        }
        if ((value & AttachmentHint.WIRED.getValue()) > 0) {
            set.add(AttachmentHint.WIRED);
        }
        if ((value & AttachmentHint.WIRELESS.getValue()) > 0) {
            set.add(AttachmentHint.WIRELESS);
        }
        if ((value & AttachmentHint.NFC.getValue()) > 0) {
            set.add(AttachmentHint.NFC);
        }
        if ((value & AttachmentHint.BLUETOOTH.getValue()) > 0) {
            set.add(AttachmentHint.BLUETOOTH);
        }
        if ((value & AttachmentHint.NETWORK.getValue()) > 0) {
            set.add(AttachmentHint.NETWORK);
        }
        if ((value & AttachmentHint.READY.getValue()) > 0) {
            set.add(AttachmentHint.READY);
        }
        if ((value & AttachmentHint.WIFI_DIRECT.getValue()) > 0) {
            set.add(AttachmentHint.WIFI_DIRECT);
        }
        attachmentHints = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<AttachmentHint> iterator() {
        return attachmentHints.iterator();
    }

    @Override
    public int size() {
        return attachmentHints.size();
    }
}
