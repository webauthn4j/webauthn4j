package com.webauthn4j.test.integration.environment

import com.webauthn4j.ctap.client.CtapService
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.data.client.Origin

/** Runtime representation of a built client platform. */
data class ClientPlatform(
    val webAuthnClient: WebAuthnClient,
    val ctapServices: List<CtapService>,
    val authenticators: List<Authenticator>,
    val origin: Origin,
    val clientPINValue: String,
) {
    /** Shortcut to the first CTAP service. */
    val ctapService: CtapService get() = ctapServices.first()
}
