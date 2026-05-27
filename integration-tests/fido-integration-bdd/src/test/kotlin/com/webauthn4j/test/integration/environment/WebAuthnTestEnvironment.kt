package com.webauthn4j.test.integration.environment

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.CtapService
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessAdaptor
import com.webauthn4j.data.client.Origin
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.cbor.CBORMapper
import tools.jackson.module.kotlin.KotlinModule

// ============================================================
// Test Environment
// ============================================================

class WebAuthnTestEnvironment internal constructor(
    val authenticators: List<Authenticator>,
    val clientPlatforms: List<ClientPlatform>,
    val relyingParty: RelyingParty,
    val scenario: StandardScenario,
) {
    val authenticator: Authenticator get() = authenticators.first()
    val clientPlatform: ClientPlatform get() = clientPlatforms.first()

    companion object {
        fun create(init: EnvironmentDsl.() -> Unit): WebAuthnTestEnvironment {
            val dsl = EnvironmentDsl().apply(init)
            return dsl.build()
        }

        fun createDefault(): WebAuthnTestEnvironment = create {
            clientPlatform { authenticator() }
            relyingParty()
        }
    }
}

// ============================================================
// DSL
// ============================================================

class EnvironmentDsl {
    private val clientPlatformDsls = mutableListOf<ClientPlatformDsl>()
    private var relyingPartyInit: (RelyingParty.Builder.() -> Unit)? = null

    fun clientPlatform(init: ClientPlatformDsl.() -> Unit = {}) {
        clientPlatformDsls.add(ClientPlatformDsl().apply(init))
    }

    fun relyingParty(init: RelyingParty.Builder.() -> Unit = {}) {
        require(relyingPartyInit == null) { "relyingParty must be declared exactly once" }
        relyingPartyInit = init
    }

    internal fun build(): WebAuthnTestEnvironment {
        require(clientPlatformDsls.isNotEmpty()) { "At least one clientPlatform must be declared" }
        requireNotNull(relyingPartyInit) { "relyingParty must be declared" }

        val objectConverter = createObjectConverter()

        val allAuthenticators = mutableListOf<Authenticator>()
        val builtClientPlatforms = clientPlatformDsls.map { cpDsl ->
            cpDsl.build(objectConverter).also { cp ->
                allAuthenticators.addAll(cp.authenticators)
            }
        }

        val relyingParty = RelyingParty.Builder().apply(relyingPartyInit!!).build()
        val defaultCp = builtClientPlatforms.first()
        val scenario = StandardScenario(relyingParty, defaultCp, objectConverter)

        return WebAuthnTestEnvironment(
            authenticators = allAuthenticators,
            clientPlatforms = builtClientPlatforms,
            relyingParty = relyingParty,
            scenario = scenario,
        )
    }

    private fun createObjectConverter(): ObjectConverter {
        val jsonMapper = JsonMapper()
        val cborMapper = CBORMapper.builder().addModule(KotlinModule.Builder().build()).build()
        return ObjectConverter(jsonMapper, cborMapper)
    }
}

class ClientPlatformDsl {
    var origin: Origin = Origin("https://example.com")
    var clientPINValue: String = "clientPIN"
    private val authenticatorBuilders = mutableListOf<Authenticator.Builder>()

    fun authenticator(init: Authenticator.Builder.() -> Unit = {}) {
        authenticatorBuilders.add(Authenticator.Builder().apply(init))
    }

    internal fun build(objectConverter: ObjectConverter): ClientPlatform {
        require(authenticatorBuilders.isNotEmpty()) { "At least one authenticator must be declared in clientPlatform" }

        val authenticators = authenticatorBuilders.map { it.build(objectConverter) }
        val ctapClients = authenticators.map { CtapClient(InProcessAdaptor(it.transport)) }
        val ctapServices = ctapClients.map { CtapService(it) }
        val webAuthnClient = WebAuthnClient(ctapClients, objectConverter)
        return ClientPlatform(webAuthnClient, ctapServices, authenticators, origin, clientPINValue)
    }
}
