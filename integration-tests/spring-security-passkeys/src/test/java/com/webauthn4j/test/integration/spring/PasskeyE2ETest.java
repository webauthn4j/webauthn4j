package com.webauthn4j.test.integration.spring;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.logging.LogEntries;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.logging.LoggingPreferences;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.virtualauthenticator.HasVirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.time.Duration;
import java.util.logging.Level;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class PasskeyE2ETest {

    @LocalServerPort
    private int port;

    private WebDriver driver;

    @BeforeEach
    void setup() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");

        LoggingPreferences logPrefs = new LoggingPreferences();
        logPrefs.enable(LogType.BROWSER, Level.ALL);
        options.setCapability("goog:loggingPrefs", logPrefs);
        
        driver = new ChromeDriver(options);
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));

        VirtualAuthenticatorOptions authOptions = new VirtualAuthenticatorOptions()
                .setTransport(VirtualAuthenticatorOptions.Transport.INTERNAL)
                .setProtocol(VirtualAuthenticatorOptions.Protocol.CTAP2)
                .setHasResidentKey(true)
                .setHasUserVerification(true)
                .setIsUserVerified(true);
        
        ((HasVirtualAuthenticator) driver).addVirtualAuthenticator(authOptions);
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }

    @Test
    void testPasskeyRegistrationAndLogin() {
        String baseUrl = "http://localhost:" + port;
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(20));

        // 1. Login with password first to register a passkey
        driver.get(baseUrl + "/login");
        driver.findElement(By.name("username")).sendKeys("user");
        driver.findElement(By.name("password")).sendKeys("password");
        driver.findElement(By.cssSelector("button[type='submit']")).click();

        try {
            // Wait for login to complete (title change or h1 element)
            wait.until(ExpectedConditions.titleIs("Spring Security Passkeys Test"));
        } catch (Exception e) {
            System.out.println("Login Failed. Page Source: " + driver.getPageSource());
            printBrowserLogs();
            throw e;
        }

        assertThat(driver.getTitle()).isEqualTo("Spring Security Passkeys Test");
        assertThat(driver.findElement(By.tagName("h1")).getText()).contains("user");

        // 2. Register a passkey
        driver.get(baseUrl + "/webauthn/register");
        driver.findElement(By.id("label")).sendKeys("My Passkey");

        // Wait for page to be fully loaded and ready
        wait.until(d -> ((JavascriptExecutor) d).executeScript("return document.readyState").equals("complete"));

        WebElement registerButton = driver.findElement(By.cssSelector("button"));
        wait.until(ExpectedConditions.elementToBeClickable(registerButton));
        registerButton.click();
        
        // Wait for registration completion
        try {
            wait.until(d -> d.getCurrentUrl().equals(baseUrl + "/") || d.getCurrentUrl().contains("success"));
        } catch (Exception e) {
            System.out.println("Registration Failed. Current URL: " + driver.getCurrentUrl());
            System.out.println("Page Source: " + driver.getPageSource());
            printBrowserLogs();
            throw e;
        }

        // 3. Logout
        if (!driver.getCurrentUrl().equals(baseUrl + "/")) {
             driver.get(baseUrl + "/");
        }
        driver.findElement(By.cssSelector("form[action='/logout'] button")).click();

        // 4. Login with Passkey
        driver.get(baseUrl + "/login");
        driver.findElement(By.id("passkey-signin")).click();
        
        // 5. Verify successful login
        wait.until(ExpectedConditions.urlToBe(baseUrl + "/"));
        
        assertThat(driver.getTitle()).isEqualTo("Spring Security Passkeys Test");
        assertThat(driver.findElement(By.tagName("h1")).getText()).contains("user");
    }

    private void printBrowserLogs() {
        try {
            LogEntries logEntries = driver.manage().logs().get(LogType.BROWSER);
            for (LogEntry entry : logEntries) {
                System.out.println("BROWSER LOG: " + entry.getLevel() + " " + entry.getMessage());
            }
        } catch (Exception e) {
            System.out.println("Failed to retrieve browser logs: " + e.getMessage());
        }
    }
}
