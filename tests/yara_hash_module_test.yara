import "hash"
rule oui {
    condition:
        hash.md5(0, filesize) == "8764605c6f388c89096b534d33565802" and
        hash.sha1(0, filesize) == "46aba99aa7158e4609aaa72b50990842fd22ae86" and
        hash.sha256(0, filesize) == "ec5aedf5ecc6bdadd4120932170d1b10f6cfa175cfda22951dfd882928ab279b"
}
