package com.webauthn4j.test.integration.quarkus;

import com.microsoft.playwright.*;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.gson.JsonObject;

@QuarkusTest
public class WebAuthnE2ETest {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnE2ETest.class);

    @TestHTTPResource
    URL url;

    private Playwright playwright;
    private Browser browser;
    private BrowserContext context;
    private Page page;

    @BeforeEach
    void setup() {
        playwright = Playwright.create();
        BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setArgs(List.of("--no-sandbox", "--disable-dev-shm-usage"));
        browser = playwright.chromium().launch(launchOptions);

        context = browser.newContext();
        page = context.newPage();

        // Surface browser issues in CI logs
        page.onConsoleMessage(msg -> {
            String type = String.valueOf(msg.type());
            String text = msg.text();
            if ("error".equalsIgnoreCase(type)) {
                log.error("BROWSER: {}", text);
            } else if ("warning".equalsIgnoreCase(type) || "warn".equalsIgnoreCase(type)) {
                log.warn("BROWSER: {}", text);
            } else {
                log.info("BROWSER [{}]: {}", type, text);
            }
        });
        page.onPageError(error -> log.error("PAGE ERROR: {}", error));
        context.onRequestFailed(req -> log.error("REQUEST FAILED: {} {}", req.method(), req.url()));
        context.onResponse(resp -> {
            int status = resp.status();
            if (status >= 500) log.error("HTTP {} {}", status, resp.url());
            else if (status >= 400) log.warn("HTTP {} {}", status, resp.url());
        });

        // Enable WebAuthn virtual authenticator (CTAP2 + internal)
        CDPSession cdp = context.newCDPSession(page);
        cdp.send("WebAuthn.enable", new JsonObject());

        JsonObject options = new JsonObject();
        options.addProperty("protocol", "ctap2");
        options.addProperty("transport", "internal");
        options.addProperty("hasResidentKey", true);
        options.addProperty("hasUserVerification", true);
        options.addProperty("isUserVerified", true);
        options.addProperty("automaticPresenceSimulation", true);

        JsonObject params = new JsonObject();
        params.add("options", options);
        cdp.send("WebAuthn.addVirtualAuthenticator", params);
    }

    @AfterEach
    void tearDown() {
        try {
            if (context != null) context.close();
        } catch (Exception ignored) { }
        try {
            if (browser != null) browser.close();
        } catch (Exception ignored) { }
        try {
            if (playwright != null) playwright.close();
        } catch (Exception ignored) { }
    }

    @Test
    void testWebAuthnRegistrationAndLogin() {
        String baseUrl = url.toString();
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        // 1. Navigate to home
        page.navigate(baseUrl + "/");

        // 2. Register
        String username = "playwrightUser";
        page.fill("#usernameRegister", username);
        page.fill("#firstName", "Playwright");
        page.fill("#lastName", "User");
        page.click("#register");

        // Wait for registration success in #result
        page.waitForSelector("text=User: " + username);
        String resultText = page.locator("#result").textContent();
        assertThat(resultText).contains("User: " + username);

        // 3. Logout (nav link)
        page.click("text=Logout");
        page.waitForSelector("text=User: <not logged in>");

        // 4. Login
        page.click("#login");
        page.waitForSelector("text=User: " + username);

        assertThat(page.locator("#result").textContent()).contains("User: " + username);
    }
}
