Android native code analysis
--------------------------------

This repository contains scripts to analyze native libraries of Android applications.


Usage:

1. Place all APKs in a folder (`apks`).

2. Extract all APKs to obtain the native libraries:
```
mkdir -p libs
pushd libs
for apk in ../apks/*.apk; do
    apktool d -f $apk
done
```

3. Run `src/parse.py apks lib_data` to generate library data.

4. Filter duplicates by hand, if necessary.

5. Run `src/analyze.py lib_data`, which outputs the results.
