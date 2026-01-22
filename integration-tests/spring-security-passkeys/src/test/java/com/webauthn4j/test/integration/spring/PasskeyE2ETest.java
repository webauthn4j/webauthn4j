package com.webauthn4j.test.integration.spring;

import com.microsoft.playwright.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.regex.Pattern;
import com.google.gson.JsonObject;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class PasskeyE2ETest {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyE2ETest.class);

    @LocalServerPort
    private int port;

    private Playwright playwright;
    private Browser browser;
    private BrowserContext context;
    private Page page;
    private CDPSession cdp;

    @BeforeEach
    void setup() {
        playwright = Playwright.create();
        BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setArgs(List.of("--no-sandbox", "--disable-dev-shm-usage"));
        browser = playwright.chromium().launch(launchOptions);

        context = browser.newContext(new Browser.NewContextOptions());
        page = context.newPage();

        // Log browser-side issues to CI output via logger
        page.onConsoleMessage(msg -> {
            String type = String.valueOf(msg.type());
            String text = msg.text();
            if ("error".equalsIgnoreCase(type)) {
                logger.error("BROWSER: {}", text);
            } else if ("warning".equalsIgnoreCase(type) || "warn".equalsIgnoreCase(type)) {
                logger.warn("BROWSER: {}", text);
            } else {
                logger.info("BROWSER [{}]: {}", type, text);
            }
        });
        page.onPageError(error -> {
            logger.error("PAGE ERROR: {}", error);
        });
        context.onRequestFailed(request -> {
            logger.error("REQUEST FAILED: {} {}", request.method(), request.url());
        });
        context.onResponse(response -> {
            int status = response.status();
            if (status >= 500) {
                logger.error("HTTP {} {}", status, response.url());
            } else if (status >= 400) {
                logger.warn("HTTP {} {}", status, response.url());
            }
        });

        // Enable WebAuthn and add a virtual authenticator (CTAP2 + internal)
        cdp = context.newCDPSession(page);
        JsonObject enableParams = new JsonObject();
        cdp.send("WebAuthn.enable", enableParams);

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
            if (context != null) {
                context.close();
            }
        }
        catch (Exception ignored) {
            //nop
        }
        try {
            if (browser != null) {
                browser.close();
            }
        } catch (Exception ignored) {
            //nop
        }
        try {
            if (playwright != null) {
                playwright.close();
            }
        } catch (Exception ignored) {
            //nop
        }
    }

    @Test
    void testPasskeyRegistrationAndLogin() {
        String baseUrl = "http://localhost:" + port;

        // 1. Login with password first to register a passkey
        page.navigate(baseUrl + "/login");
        page.fill("input[name='username']", "user");
        page.fill("input[name='password']", "password");
        page.click("button[type='submit']");
        page.waitForURL(baseUrl + "/");

        assertThat(page.title()).isEqualTo("Spring Security Passkeys Test");
        assertThat(page.locator("h1").textContent()).contains("user");

        // 2. Register a passkey
        page.navigate(baseUrl + "/webauthn/register");
        page.fill("#label", "My Passkey");
        page.click("button");

        // Wait for registration to complete: "/" or any URL containing "success"
        Pattern done = Pattern.compile("(^" + Pattern.quote(baseUrl) + "/$)|success");
        page.waitForURL(done);

        // 3. Logout (go to home to ensure logout button exists, then click)
        page.navigate(baseUrl + "/");
        page.click("form[action='/logout'] button");

        // 4. Login with Passkey
        page.navigate(baseUrl + "/login");
        page.click("#passkey-signin");
        page.waitForURL(baseUrl + "/");

        // 5. Verify successful login
        assertThat(page.title()).isEqualTo("Spring Security Passkeys Test");
        assertThat(page.locator("h1").textContent()).contains("user");
    }

}
