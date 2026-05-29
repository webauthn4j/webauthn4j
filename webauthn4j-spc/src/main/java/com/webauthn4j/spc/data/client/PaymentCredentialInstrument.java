package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class PaymentCredentialInstrument {

    private final String displayName;
    private final String icon;
    private final Boolean iconMustBeShown;
    private final String details;

    @JsonCreator
    public PaymentCredentialInstrument(
            @NotNull @JsonProperty("displayName") String displayName,
            @NotNull @JsonProperty("icon") String icon,
            @Nullable @JsonProperty("iconMustBeShown") Boolean iconMustBeShown,
            @Nullable @JsonProperty("details") String details) {
        AssertUtil.notNull(displayName, "displayName must not be null");
        AssertUtil.notNull(icon, "icon must not be null");
        this.displayName = displayName;
        this.icon = icon;
        this.iconMustBeShown = iconMustBeShown;
        this.details = details;
    }

    public PaymentCredentialInstrument(@NotNull String displayName, @NotNull String icon) {
        this(displayName, icon, null, null);
    }

    public @NotNull String getDisplayName() {
        return displayName;
    }

    public @NotNull String getIcon() {
        return icon;
    }

    public @Nullable Boolean getIconMustBeShown() {
        return iconMustBeShown;
    }

    public @Nullable String getDetails() {
        return details;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PaymentCredentialInstrument that = (PaymentCredentialInstrument) o;
        return Objects.equals(iconMustBeShown, that.iconMustBeShown) &&
                Objects.equals(displayName, that.displayName) &&
                Objects.equals(icon, that.icon) &&
                Objects.equals(details, that.details);
    }

    @Override
    public int hashCode() {
        return Objects.hash(displayName, icon, iconMustBeShown, details);
    }

    @Override
    public String toString() {
        return "PaymentCredentialInstrument(" +
                "displayName=" + displayName +
                ", icon=" + icon +
                ", iconMustBeShown=" + iconMustBeShown +
                ", details=" + details +
                ')';
    }
}
