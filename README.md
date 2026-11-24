# onn. Google TV 4K Plus firmware and recovery research

This study ties a public stock OTA for the onn. Google TV 4K Plus, codename `coffey`, to the verified-boot metadata of one retail unit. It also records the limits of stock recovery evidence for Android 14 build **`URO4.260304.092/16202347`**. The manufacturer model references are **CS116K4** and **DV6116N**. The SoC reported by Android is **Amlogic S905X5M** on platform **S7D**. [Evidence and methods](EVIDENCE.md)

## What the package establishes

- **Exact build identity.** The signed OTA targets the full `coffey` fingerprint and September 2026 patch level recorded on the TV. The catalog entry also shows an older discovery fingerprint. The package’s signed target metadata is the way to distinguish these fields.
- **Two independent checks on provenance.** The ZIP footer and A/B payload signatures verified using the SDMC OTA certificate matched against the TV’s OTA trust store. The reconstructed AVB chain also matched the digest reported by the running locked device. This ties the archive to the observed verified-boot metadata. The archive digest, individual image digests, and AVB chain digest cover different inputs.
- **Recovery support in the image.** The stock recovery fragment is in `vendor_boot`. It contains Recovery, USB ADB sideload components, and userspace fastbootd. Both this OTA and the earlier `15051976` OTA use a recovery ramdisk rather than a dedicated recovery partition. [Evidence and methods](EVIDENCE.md) · [AOSP vendor boot layout](https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions)

## What remains open

Physical entry into stock Recovery from a cold start, powered USB enumeration as a peripheral, same-build OTA acceptance, and a normal return to Android remain unverified on this unit. The active slot was `_b` during capture. Alternate-slot health and bootability were unavailable. The public full OTA is a candidate for stock servicing through supported interfaces. Its contents leave user-data restoration, bare-storage initialization, and pre-Android service recovery unresolved. [Evidence and methods](EVIDENCE.md) · [AOSP A/B updates](https://source.android.com/docs/core/ota/ab) · [AOSP fastbootd and lock requirements](https://source.android.com/docs/core/architecture/bootloader/fastbootd)

## Prior work

The OTA endpoint was publicly cataloged, and earlier owner research documented the `coffey` hardware and the move to `16202347`. AOSP documents the generic signing and recovery architecture. The independent contribution here is the end-to-end identity check from the exact public OTA through its signatures and reconstructed AVB chain, plus the assessment of which recovery steps the archived evidence actually supports. [Public OTA catalog](https://otachecker.com/ota/2915) · [Earlier coffey research](https://github.com/ajstrick81/own-the-onn/blob/main/STATUS.md) · [AOSP OTA signing](https://source.android.com/docs/core/ota/sign_builds)

[Documentation license](LICENSE.md)
