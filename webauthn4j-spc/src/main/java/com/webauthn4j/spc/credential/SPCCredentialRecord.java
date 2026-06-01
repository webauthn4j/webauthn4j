package com.webauthn4j.spc.credential;

import com.webauthn4j.credential.CredentialRecord;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public interface SPCCredentialRecord extends CredentialRecord {

    @NotNull List<BrowserBoundKey> getBrowserBoundKeys();
}
