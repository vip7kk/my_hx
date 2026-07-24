# Building dProtect

!!! info

    **dProtect** is distributed under the terms of the GNU General Public License. Please consult the [license page](license/license.md) for more details.

Building dProtect is easy - you'll need:

* a Java 17 JDK installed (required for AGP 8.0+)
* a clone of the [dProtect](https://github.com/open-obfuscator/dProtect.git) repository

You can then execute a composite build with the following Gradle command:

=== "Linux/macOS"
    ```bash
    ./gradlew assemble
    ```

=== "Windows"
    ```bash
    gradlew assemble
    ```


The artifacts will be generated in the `lib` directory. You can then execute ProGuard using the
scripts in `bin`, for example:

=== "Linux/macOS"

    ```bash
    bin/proguard.sh
    ```

=== "Windows"

    ```bash
    bin\proguard.bat
    ```

## Publish to Maven local


You can publish the artifacts to your local Maven cache (something like `~/.m2/`):

=== "Linux/macOS"
    ```bash
    ./gradlew publishToMavenLocal
    ```

=== "Windows"
    ```bash
    gradlew publishToMavenLocal
    ```

## Building a release distribution

You can build tar and zip archives with the binaries and documentation:


=== "Linux/macOS"

    ```bash
    ./gradlew distTar distZip
    ```

=== "Windows"

    ```bash
    gradlew distTar distZip
    ```

