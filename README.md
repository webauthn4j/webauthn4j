# WebAuthn4J

[![Build Status](https://travis-ci.org/webauthn4j/webauthn4j.svg?branch=master)](https://travis-ci.org/webauthn4j/webauthn4j)

A portable Java library for WebAuthn assertion verification

**This is a Proof of Concept. Not for production use for now. Design may change radically.**

## Documentation

You can find out more details from the [reference](https://webauthn4j.github.io/webauthn4j/en/).

## Build

WebAuthn4J uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later

### Checkout sources

```
git clone https://github.com/webauthn4j/webauthn4j
```

### Build all jars

```
./gradlew build
```

## Sample application

Spring Security WebAuthn is built on the top of WebAuthn4J. 
Please see [Spring Security WebAuthn sample application](https://github.com/ynojima/spring-security-webauthn).

## License

WebAuthn4J is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
