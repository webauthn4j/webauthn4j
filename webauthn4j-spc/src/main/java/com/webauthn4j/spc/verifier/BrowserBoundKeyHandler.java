package com.webauthn4j.spc.verifier;

import org.jetbrains.annotations.NotNull;

public interface BrowserBoundKeyHandler {

    void handle(@NotNull BrowserBoundKeyEvent event);
}
