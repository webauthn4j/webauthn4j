package com.webauthn4j.data.extension.client;

import com.webauthn4j.data.extension.SingleValueExtensionOutputBase;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class FIDOAppIDExclusionExtensionClientOutput extends SingleValueExtensionOutputBase<Boolean> implements AuthenticationExtensionClientOutput {

    public static final String ID = "appidExclude";

    public FIDOAppIDExclusionExtensionClientOutput(@NotNull Boolean appIdExclude) {
        super(appIdExclude);
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    public @NotNull Boolean getAppidExclude() {
        return getValue(ID);
    }

    @SuppressWarnings({"ConstantConditions", "java:S2583"})
    @Override
    public void validate() {
        // value can be null when deserialized by Jackson
        if (getValue() == null) {
            throw new ConstraintViolationException("value must not be null");
        }
    }

}
