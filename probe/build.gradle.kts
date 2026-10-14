plugins {
    id("com.android.application")
}
android {
    namespace = "dev.omega.vpn.probe"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.omega.vpn.probe"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-e2e"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
