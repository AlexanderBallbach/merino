plugins { kotlin("jvm") version "2.0.21" }

repositories { mavenCentral() }

kotlin { jvmToolchain(17) }

// No test framework dependency: the vectors runner is a plain main() so the module stays dependency-free.
val vectors by tasks.registering(JavaExec::class) {
    dependsOn("testClasses")
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("org.merino.VectorsKt")
    args(rootProject.file("../vectors").absolutePath)
}
tasks.named("check") { dependsOn(vectors) }
