# Spring Security WebAuthn

[![Build Status](https://travis-ci.org/ynojima/spring-security-webauthn.svg?branch=master)](https://travis-ci.org/ynojima/spring-security-webauthn)

Spring Security WebAuthn provides Web Authentication specification support for your Spring application.
Users can login with WebAuthn compliant authenticator.

**This is a Proof of Concept. Not for production use for now.**

## Documentation

You can find out more details from the [reference](http://) or by browsing the [javadoc](http://).

## Build

Spring Security WebAuthn uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later
- Spring Framework 5.0 or later
- Spring Security 5.0 or later

### Checkout sources

```
git clone <source repository>
```

### Build all jars

```
./gradlew build
```

### Execute sample application

```
./gradlew spring-security-webauthn-sample:bootRun
```

## License

Spring Security WebAuthn is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
