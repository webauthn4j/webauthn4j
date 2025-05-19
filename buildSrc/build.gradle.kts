plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

kotlinDslPluginOptions {
    jvmTarget.set(JavaVersion.VERSION_11.toString())
}
