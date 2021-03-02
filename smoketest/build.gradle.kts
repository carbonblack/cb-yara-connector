import com.bmuschko.gradle.docker.tasks.container.*
import com.bmuschko.gradle.docker.tasks.image.*
import org.gradle.api.GradleException
import java.io.BufferedReader

plugins {
    base
    id("com.bmuschko.docker-remote-api")
}

val osVersionClassifier: String
    get() {
        return try {
            val versionText = File("/etc/redhat-release").readText()
            when {
                versionText.contains("release 8") -> "centos8"
                else -> "centos7"
            }
        } catch (ignored: Exception) {
            "centos7"
        }
    }

fun List<String>.execute(workingDir: File? = null): String? {
    val proc = ProcessBuilder(this)
            .directory(workingDir)
            .redirectOutput(ProcessBuilder.Redirect.PIPE)
            .redirectError(ProcessBuilder.Redirect.PIPE)
            .start()

    val allText = proc.inputStream.bufferedReader().use(BufferedReader::readText)
    proc.waitFor(5, TimeUnit.SECONDS)
    return allText
}

buildDir = rootProject.buildDir

val createDockerFile = tasks.register<Dockerfile>("createSmokeTestDockerfile") {
    from(System.getenv()["BASE_IMAGE"])
    runCommand("yum -y install --disablerepo=nodesource postgresql-server sudo")
    runCommand("echo Adding cb user")
    runCommand("groupadd cb --gid 8300 && useradd --shell /sbin/nologin --gid cb --comment \"Service account for VMware Carbon Black EDR\" -M cb")
    runCommand("mkdir /postgres ; chown -R cb:cb /postgres ; chown -R cb:cb /var/run/postgresql")
    runCommand("sudo -u cb /usr/bin/initdb -D /postgres")
    runCommand("yum -y install --disablerepo=nodesource redis")
    runCommand("python3.8 -m ensurepip && python3.8 -m pip install flask pyopenssl")
}

val createSmokeTestImage = tasks.register<DockerBuildImage>("createSmokeTestImage") {
    dependsOn(createDockerFile)
    images.add("yaraconnectorsmoketest/${osVersionClassifier}:latest")
}

val username: String = System.getProperties()["user.name"].toString()

val createContainer = tasks.register<DockerCreateContainer>("createContainer") {
    dependsOn(createSmokeTestImage)
    finalizedBy(":smoketest:removeContainer")
    group = ""

    imageId.set(createSmokeTestImage.get().imageId)
    cmd.set(listOf("${projectDir}/cmd.sh", File("${rootProject.buildDir}/rpm").absolutePath, "${rootProject.projectDir.absolutePath}/smoketest"))
    hostConfig.binds.set(mapOf((project.rootDir.absolutePath) to project.rootDir.absolutePath))
}

val startContainer = tasks.register<DockerStartContainer>("startContainer") {
    dependsOn(":build")
    dependsOn(createContainer)
    finalizedBy(":smoketest:removeContainer")
    group = ""

    containerId.set(createContainer.get().containerId)
}

val tailContainer = tasks.register<DockerLogsContainer>("tailContainer") {
    dependsOn(startContainer)
    finalizedBy(":smoketest:removeContainer")
    group = ""

    follow.set(true)
    containerId.set(createContainer.get().containerId)
}

val checkStatusCode = tasks.register<DockerWaitContainer>("checkStatusCode") {
    dependsOn(tailContainer)
    finalizedBy(":smoketest:removeContainer")
    group = ""

    containerId.set(createContainer.get().containerId)

    doLast {
        if (exitCode != 0) {
            println("Smoke tests failed")
            throw GradleException("error occurred")
        }
    }
}

val removeContainer = tasks.register<DockerRemoveContainer>("removeContainer") {
    group = ""
    onlyIf {
        createContainer.get().state.failure != null ||
                startContainer.get().state.failure != null ||
                tailContainer.get().state.failure != null ||
                checkStatusCode.get().didWork
    }
    removeVolumes.set(true)
    force.set(true)
    containerId.set(createContainer.get().containerId)

    doFirst {
        println("Deleting created smoketest container")
        onError {
            // ignore exception if container does not exist otherwise throw it
            if (!this.message!!.contains("No such container"))
                throw this
        }
    }
}

val smoketest = tasks.register<Task>("runSmokeTest") {
    dependsOn(checkStatusCode)
    group = "Verification"
    description = "Executes the smoke test suite."
}

tasks.named("build") {
    this.finalizedBy(smoketest)
}