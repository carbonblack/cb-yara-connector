plugins {
    base
    id("com.carbonblack.gradle-dockerized-wrapper") version "1.2.1"

    // Pinned versions of plugins used by subprojects
    id("com.carbonblack.gradle-connector-python") version "2.1.1"
    id("com.jfrog.artifactory") version "4.15.1" apply false
    id("com.palantir.git-version") version "0.12.3" apply false
    id("com.bmuschko.docker-remote-api") version "6.4.0" apply false
}

// This is running in a docker container so this value comes from the container OS.
val osVersionClassifier: String
    get() {
        return try {
            val versionText = File("/etc/redhat-release").readText()
            when {
                versionText.contains("release 8") -> "el8"
                else -> "el7"
            }
        } catch (ignored: Exception) {
            "el7"
        }
    }

buildDir = file("build/$osVersionClassifier")

val buildRpm = tasks.named("buildRpm").configure {
    dependsOn(tasks.named("runPyTest"))
}

val buildTask = tasks.named("build").configure {
    dependsOn(tasks.named("buildRpm"))
}

python {
    sourceExcludes.add("smoketest/")
}