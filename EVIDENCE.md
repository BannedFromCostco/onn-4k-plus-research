# Evidence for the coffey 16202347 stock OTA

## Device and package identity

| Field | Captured or signed value |
| --- | --- |
| Device and board | `coffey`, onn. Google TV 4K Plus, S905X5M / S7D |
| Full fingerprint | `onn/coffey/coffey:14/URO4.260304.092/16202347:user/release-keys` |
| Android and patch level | Android 14, API 34, system and vendor patch date `2026-09-01` |
| Bootloader | `01.01.260305.112513` |
| Active boot state | Slot `_b`, locked, AVB green, dm-verity enforcing |
| Package metadata | `pre-device=coffey`, `ota-type=AB`, full payload, target timestamp `1787905194` |
| ZIP byte length | 912,195,771 |

The device sample came from an authorized Android shell. Package metadata, signed payload records, and recovery files were inspected offline. The catalog’s discovery fingerprint differs from the target fingerprint inside the package. [Catalog entry](https://otachecker.com/ota/2915) · [Google-hosted stock OTA](https://android.googleapis.com/packages/ota-api/package/3e9b5443c378efc766bd089888f5b7cf77226932.zip) · [AOSP OTA metadata](https://source.android.com/docs/core/ota/tools)

## Integrity and authenticity

| Object | SHA-256 |
| --- | --- |
| Complete ZIP | `edb325094dc46e00bd2866c5552371a9989e16849491552cab8fbf60672222dd` |
| OTA signing certificate, DER | `e5f0c8c29419b5c05b5e6a092792a1149ac5e968c5cae13d2c03ca99129d4ee7` |
| Complete `payload.bin` | `439aeed7733c1e62ab9471cace06d1d04df10bde873f9605e89bbb77a66a298a` |
| Payload metadata range covered by `METADATA_HASH` | `92e20b031cf2ea0842cf66317b42e0dcfac4447c7134a53210907289059aa3d7` |
| Ordered AVB chain metadata | `6ef982d2bf9af582cba0f2de64af709a061add0145b785981a2d0a23fa8b3fb9` |

OpenSSL verified the whole-file ZIP signature against the OEM certificate matched in normal Android and in the stock recovery ramdisk. The A/B payload metadata and full-payload RSA-4096/SHA-256 signatures also verified. The payload digest and metadata digest matched the package’s declared values. Seventeen reconstructed partition images matched the authenticated payload manifest. Concatenating the verified metadata for `vbmeta`, `boot`, `oem`, and `vbmeta_system` in chain order produced 17,088 bytes. Its digest matches the saved running device property. The publication audit separately rehashed the archived ZIP, payload, and payload metadata, and confirmed the embedded certificate matches the archived certificate. [AOSP release signing](https://source.android.com/docs/core/ota/sign_builds) · [AOSP payload format](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto) · [AVB digest definition](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/README.md#the-vbmeta-digest)

## Recovery evidence

| Status | Finding |
| --- | --- |
| Confirmed in the signed package | `boot` carries the kernel. `init_boot` carries the generic ramdisk. `vendor_boot` carries a typed recovery ramdisk with stock Recovery, sideload services, fastbootd and the OTA trust certificate. The manifest has no standalone `recovery` or `userdata` target. |
| Confirmed metadata comparison | The full A/B OTA targets the device and build in the capture. It declares no source build prerequisite or wipe flag. Target timestamp and security patch level agree with the installed values. |
| Inference from reference code | The AOSP timestamp checks reviewed permit equality. The package meets those checked conditions. OEM installer behavior, hardware rollback state, available snapshot space, and preservation of user data remain unknown. |
| Unresolved on the device | Cold Recovery entry, USB enumeration in Recovery or fastbootd, acceptance of the same-build OTA, successful boot afterward, and a recovery route when stock Recovery itself is unavailable. |

[AOSP vendor ramdisk layout](https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions) · [AOSP recovery package checks](https://android.googlesource.com/platform/bootable/recovery/+/8ff84d7cfb1d51221f61ad6ebd97434b6f8b658a/install.cpp) · [AOSP fastbootd](https://source.android.com/docs/core/architecture/bootloader/fastbootd)
