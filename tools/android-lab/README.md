# Foldable OCR tap patch for Manatan 6.2.13

This is an exact-version **ARM64 binary patch**, not a rebuild of the reader.
The public repository does not contain the Flutter reader implementation shipped
in the investigated Android release. The script accepts a user's local original
APK or extracted library and creates a patched library; no application binaries,
decompiled sources, private keys, or instrumentation libraries are included here.

The patch fixes a reproduced upper-page OCR hit-test failure when a tall page is
displayed in single-page, fit-width mode and panned on an unfolded phone. A
PhotoView child can remain visible outside its layout box. Flutter's generic
`RenderBox.hitTest` then rejects the point before testing that visible child.

The generic function changes only for the exact PhotoView box/delegate class
pair in this build: box CID 6400 and delegate CID 3813. Ordinary render boxes
retain their original bounds rejection. Contained points follow the original
path. For the matching PhotoView pair, outside points reach the existing child
hit test, which still decides whether the actual image child accepts the point.
The patch does not globally disable reader bounds checks or alter OCR geometry.

**Border cropping is deferred and is not implemented.** A later report of word
highlights appearing without a dictionary popup was not diagnosed or fixed by
this patch; investigation of that report was stopped at the user's request.

## Compatibility

- Investigated release: Manatan 6.2.13, Android ARM64 (`arm64-v8a`).
- Required original `libapp.so` SHA-256:
  `7ea743dbf674ad42650030fec40aba9dcfe95bd0f4dfdd482f7fbc4410e3be9d`.
- Reproducible patched `libapp.so` SHA-256:
  `2d5ac822b46902139c592e67a01163492467f12403963189f7107fd3a3f4ccbf`.

Version labels alone are insufficient: the input hash must match. The tool
rejects another release, another ABI, and already-patched input. Class IDs and
addresses are build-specific; do not remove the hash guard to target an update.

## Run offline

Use Python 3 and an isolated environment. From the repository root:

```sh
python -m venv .venv
# Activate .venv for your shell, then:
python -m pip install -r tools/android-lab/requirements.txt
python tools/android-lab/patch_foldable_taps.py --input-apk /path/to/original.apk --output-lib /path/to/local-lab/libapp.so
```

Alternatively, supply an already-extracted original ARM64 library:

```sh
python tools/android-lab/patch_foldable_taps.py --input-lib /path/to/original/libapp.so --output-lib /path/to/local-lab/libapp.so
```

The input remains unchanged. Beside the output, the tool writes a JSON report,
the trampoline assembly and disassembly, and the individual emulator results.
It does not contact a phone, install an app, access app data, or sign an APK.

To run the ARM64 branch tests without any proprietary input:

```sh
python tools/android-lab/patch_foldable_taps.py --self-test
```

## Static verification

Every patch build runs 90 Unicorn cases using the actual encoded ARM64 branch
and trampoline: ordinary and neighboring class IDs, contained/outside points,
the target PhotoView pair, and null/Smi delegates. The checks verify original
branch destinations, live registers, and saved stack data. Capstone independently
decodes the generated instructions.

The original native code change is one four-byte branch at VA `0xab22a0`. A
76-byte trampoline and relocated ELF program table occupy a new 16-KiB-aligned
read/execute segment. The verifier checks all original section metadata and
addresses, permits original section byte changes only at that instruction, and
checks the exact reviewed output digest. No existing code padding is reused and
no new dynamic dependency is added. The trampoline neither calls nor allocates;
its temporary registers are overwritten by the original continuation before
their next reads. Other original-file byte changes are limited to ELF header
fields describing the relocated table.

## Recorded device validation and reproduction

The original failure and the permanent patch were tested through ADB on one
Honor PNM-AN10 foldable in its unfolded configuration. The display was
2172 x 2352 pixels, with a 724 x 784 logical viewport. In the failing case, a
tall fit-width page had approximately 724 x 1050 logical dimensions. After
panning, a visible upper-page tap reached the PhotoView layout box with negative
local Y, so its bounds test rejected the point. With the permanent patch in a
separate Lab APK, upper bubble activation and subsequent word lookup succeeded.
That is device evidence for this case; the emulator checks do not establish
behavior on other devices or all reader modes.

Manual regression procedure:

1. In a separate Lab installation, use an OCR-ready page taller than the unfolded
   viewport; select single-page reading and fit-width scaling.
2. Pan until the page's upper speech bubbles are visible. A downward swipe of
   roughly 450 physical pixels reproduced the issue in the investigated setup.
3. Tap an upper bubble and then a word. Verify bubble activation and dictionary
   lookup, and compare with lower-page OCR taps.
4. Check reader controls, ordinary taps outside the image, and navigating to a
   different page. Child hit testing must continue to reject empty areas.

## Packaging and existing data

Runtime testing used a separate `com.mangatan.lab` package signed with a local
Lab key. This directory produces only the patched native library. A Lab APK
repackager must also use a distinct package/provider identity while preserving
the application's actual component class names, then align and sign the result
with a key controlled by the tester. Keep that key local. Updates to an existing
Lab installation must use its existing Lab key to retain its app data.

A locally signed APK cannot update the original developer-signed installation
without the original signing key. Installing Lab does not migrate the original
application's private data. Preserve the original installation when retaining
all its data matters; uninstalling it to get around a signature mismatch is not
a data-preserving update. This patch includes no migration or backup mechanism.
