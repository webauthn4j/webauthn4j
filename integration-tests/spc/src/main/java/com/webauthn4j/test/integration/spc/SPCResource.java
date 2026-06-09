package com.webauthn4j.test.integration.spc;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.spc.credential.BrowserBoundKey;
import com.webauthn4j.spc.credential.SPCCredentialRecord;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.SPCRegistrationParameters;
import com.webauthn4j.spc.data.SecurePaymentConfirmationRequest;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import org.jetbrains.annotations.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.*;

@Path("/api")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SPCResource {

    private static final int PORT = 8080;
    private static final String RP_HOST = "bank.localhost";
    private static final String MERCHANT_HOST = "merchant.localhost";
    private static final Origin RP_ORIGIN = new Origin("http://" + RP_HOST + ":" + PORT);
    private static final Origin MERCHANT_BROWSER_ORIGIN = new Origin("http://" + MERCHANT_HOST + ":" + PORT);
    private static final Origin MERCHANT_PAYEE_ORIGIN = new Origin("https://" + MERCHANT_HOST);
    private static final String RP_ID = RP_HOST;
    private static final String ICON_DATA_URL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final SPCManager spcManager = new SPCManager();

    private Challenge currentChallenge;
    private SPCCredentialRecord storedCredentialRecord;
    private byte[] storedCredentialId;

    // === Registration (called from bank.localhost) ===

    @GET
    @Path("/register/options")
    public Response getRegistrationOptions() {
        currentChallenge = new DefaultChallenge();

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions =
                new AuthenticationExtensionsClientInputs.BuilderForRegistration()
                        .set("payment", Map.of("isPayment", true))
                        .build();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(RP_ID, "Example Bank"),
                new PublicKeyCredentialUserEntity(new byte[]{1, 2, 3, 4}, "testuser", "Test User"),
                currentChallenge,
                List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                60000L,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.PLATFORM,
                        ResidentKeyRequirement.REQUIRED,
                        UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                extensions
        );

        String json = objectConverter.getJsonMapper().writeValueAsString(options);
        return Response.ok(json, MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Path("/register/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response verifyRegistration(String registrationResponseJSON) {
        try {
            ServerProperty serverProperty = new ServerProperty(RP_ORIGIN, RP_ID, currentChallenge, null);
            SPCRegistrationParameters params = new SPCRegistrationParameters(
                    serverProperty,
                    List.of(new PublicKeyCredentialParameters(
                            PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)));

            RegistrationData registrationData = spcManager.verifyRegistrationResponseJSON(registrationResponseJSON, params);

            storedCredentialRecord = new SimpleSPCCredentialRecord(
                    registrationData.getAttestationObject(),
                    registrationData.getCollectedClientData());
            storedCredentialId = registrationData.getAttestationObject()
                    .getAuthenticatorData().getAttestedCredentialData().getCredentialId();

            return Response.ok("OK").build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    // === Authentication (called from merchant.localhost) ===

    @GET
    @Path("/authenticate/options")
    public Response getAuthenticationOptions() {
        currentChallenge = new DefaultChallenge();

        SecurePaymentConfirmationRequest spcRequest = new SecurePaymentConfirmationRequest(
                currentChallenge,
                RP_ID,
                List.of(storedCredentialId),
                new PaymentCredentialInstrument("Test Card", ICON_DATA_URL),
                60000L,
                "Test Merchant",
                MERCHANT_PAYEE_ORIGIN,
                null, null, null, null, null
        );

        Map<String, Object> total = new LinkedHashMap<>();
        total.put("label", "Total");
        Map<String, Object> amount = new LinkedHashMap<>();
        amount.put("currency", "USD");
        amount.put("value", "5.00");
        total.put("amount", amount);

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("spcData", spcRequest);
        options.put("total", total);

        String json = objectConverter.getJsonMapper().writeValueAsString(options);
        return Response.ok(json, MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Path("/authenticate/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response verifyAuthentication(String authenticationResponseJSON) {
        try {
            // Note: origin is the MERCHANT's origin, not the RP's origin.
            // This is the key cross-origin aspect of SPC.
            ServerProperty serverProperty = ServerProperty.builder()
                    .origin(MERCHANT_BROWSER_ORIGIN).rpId(RP_ID).challenge(currentChallenge)
                    .topOrigin(MERCHANT_BROWSER_ORIGIN).build();
            SPCAuthenticationParameters params = new SPCAuthenticationParameters(
                    serverProperty, storedCredentialRecord,
                    new PaymentCurrencyAmount("USD", "5.00"),
                    new PaymentCredentialInstrument("Test Card", ICON_DATA_URL),
                    "Test Merchant", MERCHANT_PAYEE_ORIGIN);

            spcManager.verifyAuthenticationResponseJSON(authenticationResponseJSON, params);
            return Response.ok("OK").build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    private static class SimpleSPCCredentialRecord extends CredentialRecordImpl implements SPCCredentialRecord {
        SimpleSPCCredentialRecord(AttestationObject attestationObject, com.webauthn4j.data.client.CollectedClientData clientData) {
            super(attestationObject, clientData, null, null);
        }

        @Override
        public @NotNull List<BrowserBoundKey> getBrowserBoundKeys() {
            return List.of();
        }
    }
}
