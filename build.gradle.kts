import java.io.File

plugins {
    base
    id("com.carbonblack.gradle-dockerized-wrapper") version "1.2.1"

    // Pinned versions of plugins used by subprojects
    id("com.carbonblack.gradle-python-rpm") version "2.2.2" 
    id("com.jfrog.artifactory") version "4.15.1" apply false
    id("com.palantir.git-version") version "0.12.3" apply false
    id("com.bmuschko.docker-remote-api") version "6.4.0" apply false
}


// This is running in a docker container so this value comes from the container OS.

object OSVersion {
    enum class OSType {
        UNKNOWN, EL6, EL7, EL8, PHOTON4
    }

    @Suppress("MemberVisibilityCanBePrivate")
    val version by lazy {
        val redhatReleaseFile = File("/etc/redhat-release")
        val photonReleaseFile = File("/etc/photon-release")

        when {
            redhatReleaseFile.exists() -> {
                val versionText = redhatReleaseFile.readText()
                when {
                    versionText.contains("release 6") -> OSType.EL6
                    versionText.contains("release 7") -> OSType.EL7
                    versionText.contains("release 8") -> OSType.EL8
                    else -> throw Exception("Unknown CentOS Version")
                }
            }
            photonReleaseFile.exists() -> {
                val versionText = File("/etc/photon-release").readText()
                when {
                    versionText.contains("VMware Photon OS 4") -> OSType.PHOTON4
                    else -> throw Exception("Unknown Photon OS Version")
                }
            }
            else -> {
                OSType.UNKNOWN
            }
        }
    }

    val classifier: String
        get() = when(version) {
            OSType.EL6 -> "el6"
            OSType.EL7 -> "el7"
            OSType.EL8 -> "el8"
            OSType.PHOTON4 -> "ph4"
            OSType.UNKNOWN -> "unknown"
        }

    val isEl6
        get() = version == OSType.EL6

    val isEl7
        get() = version == OSType.EL7

    val isEl8
        get() = version == OSType.EL8

    val isPhoton4
        get() = version == OSType.PHOTON4
}

val osVersionClassifier = OSVersion.classifier 


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
