# JSDroid Dev Log

## What Was Changed

The main fixes were made in `JSDroid/src/tool/entryForAllApks/EntryForAll.java` to make the tool work correctly on macOS/Linux paths and classpaths.

- Replaced Windows-only app name parsing with cross-platform parsing using `File.getName()` and extension stripping.
- Fixed Soot classpath construction to use `File.pathSeparator` and absolute paths under `JSDroid/lib` and `JSDroid/bin`.
- Added Android platform path normalization:
  - Accept direct `android.jar`
  - Accept SDK root containing `platforms`
  - Accept project root by resolving bundled `android--1/android.jar` when available
- Improved Android jar setup for Soot:
  - Use `set_force_android_jar(...)` when a concrete `android.jar` is found
  - Fall back to `set_android_jars(...)` otherwise

## Why The Original Output Looked Wrong

`Lines of code` and several result fields were not useful because analysis setup was effectively misconfigured for this environment:

- Path handling assumed Windows separators
- Classpath entries were built with `;` and root `/lib/...` paths
- Android platform path input was often interpreted incorrectly

With these fixed, analysis now runs with the correct runtime context.

## How To Compile

This project is an Eclipse-style Java project (no Maven/Gradle wrapper in this repo).  
Compile from `JSDroid/JSDroid` using Java 8 and GBK source encoding:

```bash
cd "/Users/mathiasgredal/git/test/tools/JSDroid/JSDroid"

"/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home/bin/javac" \
  -J-Dfile.encoding=GBK -encoding GBK \
  -cp "lib/soot-trunk.jar:lib/tools.jar:lib/android-support-v4.jar:lib/commons-beanutils-1.7.0.jar:lib/commons-collections-3.2.jar:lib/commons-lang-2.4.jar:lib/commons-logging-1.1.jar:lib/dom4j-1.6.1.jar:lib/android.jar:lib/jxl.jar:lib/substance.jar" \
  -d bin $(rg --files src -g "*.java")
```

## How To Run

Run the GUI entrypoint from compiled classes:

```bash
cd "/Users/mathiasgredal/git/test/tools/JSDroid/JSDroid"

JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home" \
"$JAVA_HOME/bin/java" \
  -cp "bin:lib/*" \
  tool.GUI.userWindowForAll \
  "/Users/mathiasgredal/git/test/tools/JSDroid/android--1"
```

Notes:

- The argument is the Android platform location (or a path that can resolve to an `android.jar`), not the APK folder.
- In the UI:
  1. Choose APK directory
  2. Show APK list
  3. Select apps
  4. Start detection
  5. Show results

## Gitignore Setup

Repository `.gitignore` was expanded to cover:

- OS/editor files (`.DS_Store`, `.idea`, `.vscode`)
- build outputs (`JSDroid/bin`, classes, crash logs)
- generated outputs (`Results.xls`)
- local agent/debug files (`.cursor`)
