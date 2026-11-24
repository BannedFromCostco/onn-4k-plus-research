# Reproducing the coffey OTA verification

This procedure covers the signed stock Android 14 OTA for the onn. Google TV 4K Plus, `coffey`, hardware references `CS116K4` and `DV6116N`, build **`URO4.260304.092/16202347`**. Match the complete fingerprint before comparing an archive or derived boot image.

| Reference | Scope |
| --- | --- |
| `onn/coffey/coffey:14/URO4.260304.092/16202347:user/release-keys` | Exact target of this verifier. [OTA #2915](https://otachecker.com/ota/2915) |
| `onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys` | Earlier 4K Plus package with an inspected stock recovery ramdisk. Same codename, different build. [OTA #2594](https://otachecker.com/ota/2594) |
| `onn/jarvis/SNA:14/URO4.260304.092/16202347:user/release-keys` | A different device sharing the build number. [OTA #2921](https://otachecker.com/ota/2921) |

## Verify a local OTA

Use Python 3.11 or newer, the [Python verifier](verify_coffey_ota.py), and a local copy of the stock package. The optional second mode requires OpenSSL 3.x and about 1 GB of free temporary disk space for the signed ZIP range. The temporary copy is removed when the verifier exits normally or reports an error.

```text
python verify_coffey_ota.py coffey-16202347-ota.zip
python verify_coffey_ota.py coffey-16202347-ota.zip --openssl openssl
```

The default mode checks the archive SHA-256, target fingerprint, embedded certificate fingerprint, payload SHA-256 and metadata SHA-256, then lists the 17 manifest partitions. The optional mode verifies the ZIP footer CMS signature and both A/B RSA signatures using the certificate whose DER fingerprint is pinned in the script. The original study matched that pin to the retail unit’s OTA trust store. The verifier operates on local files and leaves the source ZIP intact. [Google-hosted package](https://android.googleapis.com/packages/ota-api/package/3e9b5443c378efc766bd089888f5b7cf77226932.zip) · [Published evidence](EVIDENCE.md) · [AOSP OTA signatures](https://source.android.com/docs/core/ota/sign_builds)

A successful default run prints the target fingerprint, confirms the four matching SHA-256 values, and lists 17 partition names. A successful OpenSSL run also prints that the ZIP CMS and both A/B RSA signatures verified. A mismatch exits with a nonzero status.

On this archive, `METADATA_SIZE=39739` covers the payload header and manifest. The 523-byte embedded metadata signature follows that range. The complete `payload.bin` hash covers both signatures. The signature verification hashes use their own signed ranges. [AOSP update payload format](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto)

## Identify reconstructed boot artifacts

The saved analysis checked the full bytes of these reconstructed images against the signed payload manifest. The values cover each complete image, including its padding.

| Image | Bytes | SHA-256 |
| --- | ---: | --- |
| `boot` | 67,108,864 | `6cf3ee4b29c1bb44ad5baba66ced2a7c38752f7ab7103b548303829bfa3795da` |
| `init_boot` | 8,388,608 | `390b7d6ae2c429dbf2366aa05241f34d111b61b1a6318e3e1bfaa742be1a2ad8` |
| `vendor_boot` | 67,108,864 | `99d9eea6559bf1d45e95a4502e92b27c1cdb8f1969673cbe54e53ca62cef7c88` |
| `vbmeta` | 12,288 | `561f1e4e2fcf8e500fd8f866050d39b95d7442573ea0deb77010c81b977c03cf` |

Compute the SHA-256 of a reconstructed image with this command.

```text
python -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path('vendor_boot.img').read_bytes()).hexdigest())"
```

The verifier checks package signatures and manifest structure. Reconstruction and AVB-chain comparison are separate analyses. A verified archive and a recovery image containing USB sideload still leave cold entry, powered USB enumeration in peripheral mode, and same-build acceptance open. USB-C hubs working in normal Android demonstrate the opposite USB role from the PC-to-TV recovery transport. [AOSP vendor boot layout](https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions) · [AOSP fastbootd](https://source.android.com/docs/core/architecture/bootloader/fastbootd)
