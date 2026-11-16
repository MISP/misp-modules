# ADTimeline CSV fixture provenance

`timeline_example.test.csv` contains three synthetic observations (ordinary attribute metadata, a removed member link, and an altRecipient link with the FILETIME zero sentinel). It was serialized by the actual PowerShell `Export-Csv` command in `reproduce.ps1`, preserving semicolons, embedded quotes, BOM and large textual USNs. No AD collection or production data is involved.

The field order and export delimiter/NoTypeInformation settings follow the replication-metadata loops and final export in ANSSI-FR/ADTimeline commit `fa570aa15a03614b8dd1ea956abb556f47f4f453`, `ADTimeline.ps1` (blob `27040701abae1643a086180b794e081cfb64cf2e`). Upstream describes the timeline timestamp as UTC and its partial last-change semantics in README.md. The fixture uses ISO XML-style metadata timestamps; tests separately cover localized/unsupported values.

Reproduce with PowerShell 7 using:

```sh
docker run --rm -v "$PWD/tests/fixtures/adtimeline:/fixtures" mcr.microsoft.com/powershell:7.4-debian-12 pwsh -NoProfile -File /fixtures/reproduce.ps1
```

PowerShell reported version 7.4.6. The generation image digest was `sha256:206a748b34deec1b64553fcfa92294fc871c2df5855e9f340df172756bef201f`. `utf8BOM` explicitly reproduces the BOM behavior of Windows PowerShell's `-Encoding UTF8`; ADTimeline itself is not run on Linux. Tests also transcode the same CSV serialization into UTF-16 BOM encodings. A full Windows ADTimeline collection remains a separate integration check.
