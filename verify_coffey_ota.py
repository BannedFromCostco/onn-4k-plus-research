#!/usr/bin/env python3
"""Verify the archived coffey 16202347 OTA from a local ZIP."""

# SPDX-License-Identifier: MIT
# Copyright 2026 BannedFromCostco

import argparse
import base64
import hashlib
import os
import ssl
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

ARCHIVE_SIZE = 912_195_771
ARCHIVE_SHA = "edb325094dc46e00bd2866c5552371a9989e16849491552cab8fbf60672222dd"
CERT_SHA = "e5f0c8c29419b5c05b5e6a092792a1149ac5e968c5cae13d2c03ca99129d4ee7"
METADATA_SHA = "92e20b031cf2ea0842cf66317b42e0dcfac4447c7134a53210907289059aa3d7"
PAYLOAD_SHA = "439aeed7733c1e62ab9471cace06d1d04df10bde873f9605e89bbb77a66a298a"
FINGERPRINT = "onn/coffey/coffey:14/URO4.260304.092/16202347:user/release-keys"
CHUNK = 8 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_exact(stream, count):
    data = stream.read(count)
    require(len(data) == count, "unexpected end of file")
    return data


def bounded_blocks(stream, count):
    while count:
        block = read_exact(stream, min(count, CHUNK))
        count -= len(block)
        yield block


def properties(data):
    return dict(line.split("=", 1) for line in data.decode().splitlines() if "=" in line)


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        require(pos < len(data), "incomplete protobuf integer")
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError("oversized protobuf integer")


def fields(data):
    """Read only the standard wire types used by this pinned payload."""
    pos = 0
    while pos < len(data):
        tag, pos = varint(data, pos)
        number, wire = divmod(tag, 8)
        require(number > 0, "invalid protobuf field number")
        if wire == 0:
            value, pos = varint(data, pos)
        else:
            require(wire in (1, 2, 5), "unsupported protobuf field type")
            if wire == 2:
                size, pos = varint(data, pos)
            else:
                size = 8 if wire == 1 else 4
            end = pos + size
            require(end <= len(data), "protobuf field outside its message")
            raw = data[pos:end]
            pos = end
            value = raw if wire == 2 else int.from_bytes(raw, "little")
        yield number, value


def unique_field(data, number):
    values = [value for field, value in fields(data) if field == number]
    require(len(values) == 1, f"unexpected count for protobuf field {number}")
    return values[0]


def inspect_payload(archive, props):
    with archive.open("payload.bin") as payload:
        header = read_exact(payload, 24)
        version, manifest_size, signature_size = struct.unpack(">QQI", header[4:])
        require(header[:4] == b"CrAU" and version == 2, "unexpected OTA payload header")
        require(
            len(header) + manifest_size == int(props["METADATA_SIZE"]),
            "payload metadata size differs from its declared value",
        )
        manifest = read_exact(payload, manifest_size)
        metadata_signature = read_exact(payload, signature_size)
        metadata = header + manifest + metadata_signature
        require(
            hashlib.sha256(header + manifest).hexdigest()
            == METADATA_SHA == base64.b64decode(props["METADATA_HASH"]).hex(),
            "payload metadata SHA-256 differs",
        )
        operations_size = unique_field(manifest, 4)
        signature_end_size = unique_field(manifest, 5)
        names = [
            unique_field(partition, 1).decode()
            for number, partition in fields(manifest)
            if number == 13
        ]
        require(len(names) == len(set(names)) == 17, "unexpected partition names or count")
        require(
            len(metadata) + operations_size + signature_end_size == int(props["FILE_SIZE"]),
            "payload length disagrees with its manifest and properties",
        )
        signed_metadata = hashlib.sha256(header + manifest)
        signed_payload = signed_metadata.copy()
        full_payload = hashlib.sha256(metadata)
        for block in bounded_blocks(payload, operations_size):
            signed_payload.update(block)
            full_payload.update(block)
        payload_signature = read_exact(payload, signature_end_size)
        full_payload.update(payload_signature)
        require(not payload.read(1), "unaccounted trailing payload data")
        require(
            full_payload.hexdigest()
            == PAYLOAD_SHA == base64.b64decode(props["FILE_HASH"]).hex(),
            "full payload SHA-256 differs",
        )
    return names, (metadata_signature, signed_metadata.digest()), (
        payload_signature, signed_payload.digest()
    )


def openssl_checked(executable, label, *arguments):
    result = subprocess.run(
        [executable, *arguments], capture_output=True, check=False
    )
    require(result.returncode == 0, f"OpenSSL failed to verify {label}")


def verify_signatures(data, certificate, signatures, executable):
    with tempfile.TemporaryDirectory(prefix="coffey-ota-verify-") as directory:
        work = Path(directory)
        pem = work / "certificate.pem"
        pem.write_bytes(certificate)
        footer_signature = work / "zip-signature.der"
        signed_zip = work / "signed-zip"
        data.seek(-6, 2)
        offset, marker, comment_size = struct.unpack("<3H", read_exact(data, 6))
        require(marker == 0xFFFF and 6 < offset <= comment_size, "invalid OTA ZIP footer")
        data.seek(-offset, 2)
        footer_signature.write_bytes(read_exact(data, offset - 6))
        data.seek(0)
        with signed_zip.open("wb") as output:
            for block in bounded_blocks(data, ARCHIVE_SIZE - comment_size - 2):
                output.write(block)
        openssl_checked(
            executable, "ZIP CMS signature",
            "cms", "-verify", "-binary", "-inform", "DER", "-in", footer_signature,
            "-content", signed_zip, "-certfile", pem, "-nointern", "-noverify",
            "-out", os.devnull,
        )
        signed_zip.unlink()
        public_key = work / "public-key.pem"
        openssl_checked(
            executable, "certificate public key", "x509", "-in", pem, "-pubkey",
            "-noout", "-out", public_key,
        )
        for label, (records, digest) in zip(("metadata", "payload"), signatures):
            signed = unique_field(records, 1)
            signature = unique_field(signed, 2)
            require(len(signature) == 512, f"unexpected {label} signature length")
            digest_file = work / f"{label}.sha256"
            signature_file = work / f"{label}.sig"
            digest_file.write_bytes(digest)
            signature_file.write_bytes(signature)
            openssl_checked(
                executable, f"{label} RSA signature", "pkeyutl", "-verify",
                "-pubin", "-inkey", public_key, "-in", digest_file,
                "-sigfile", signature_file, "-pkeyopt", "digest:sha256",
            )


def verify(path, openssl):
    with path.open("rb") as data:
        require(data.seek(0, 2) == ARCHIVE_SIZE, "unexpected OTA ZIP byte length")
        data.seek(0)
        require(
            hashlib.file_digest(data, "sha256").hexdigest() == ARCHIVE_SHA,
            "OTA ZIP does not match the reference SHA-256",
        )
        with zipfile.ZipFile(data) as archive:
            target = properties(archive.read("META-INF/com/android/metadata"))
            require(
                target.get("pre-device") == "coffey"
                and target.get("post-build") == FINGERPRINT
                and target.get("ota-type") == "AB",
                "unexpected OTA target",
            )
            certificate = archive.read("META-INF/com/android/otacert")
            der = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
            require(hashlib.sha256(der).hexdigest() == CERT_SHA, "OTA certificate SHA-256 differs")
            props = properties(archive.read("payload_properties.txt"))
            names, metadata_sig, payload_sig = inspect_payload(archive, props)
        if openssl:
            verify_signatures(data, certificate, (metadata_sig, payload_sig), openssl)
    print("Target:", FINGERPRINT)
    print("Matched ZIP, certificate, payload and metadata SHA-256 values.")
    print("Signed manifest partition names:" if openssl else "Manifest partition names:")
    print(", ".join(names))
    if openssl:
        print("Verified ZIP CMS and both A/B RSA signatures against the pinned certificate.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--openssl", metavar="EXECUTABLE", help="optional OpenSSL program for signature checks"
    )
    args = parser.parse_args()
    try:
        verify(args.archive, args.openssl)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Verification failed: {exc}\n")


if __name__ == "__main__":
    main()
