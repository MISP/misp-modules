arch_type_mapping = {
    "ANDROID": "parse_apk",
    "LINUX": "parse_elf",
    "WINDOWS": "parse_pe",
}
domain_object_mapping = {
    "@ip": {"type": "ip-dst", "object_relation": "ip"},
    "@name": {"type": "domain", "object_relation": "domain"},
}
dropped_file_mapping = {
    "@entropy": {"type": "float", "object_relation": "entropy"},
    "@file": {"type": "filename", "object_relation": "filename"},
    "@size": {"type": "size-in-bytes", "object_relation": "size-in-bytes"},
    "@type": {"type": "mime-type", "object_relation": "mimetype"},
}
dropped_hash_mapping = {
    "MD5": "md5",
    "SHA": "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
}
elf_object_mapping = {
    "epaddr": "entrypoint-address",
    "machine": "arch",
    "osabi": "os_abi",
}
elf_section_flags_mapping = {
    "A": "ALLOC",
    "I": "INFO_LINK",
    "M": "MERGE",
    "S": "STRINGS",
    "T": "TLS",
    "W": "WRITE",
    "X": "EXECINSTR",
}
file_object_fields = ("filename", "md5", "sha1", "sha256", "sha512", "ssdeep")
file_object_mapping = {
    "entropy": {"type": "float", "object_relation": "entropy"},
    "filesize": {"type": "size-in-bytes", "object_relation": "size-in-bytes"},
    "filetype": {"type": "mime-type", "object_relation": "mimetype"},
}
file_references_mapping = {
    "fileCreated": "creates",
    "fileDeleted": "deletes",
    "fileMoved": "moves",
    "fileRead": "reads",
    "fileWritten": "writes",
}
network_behavior_fields = ("srcip", "dstip", "srcport", "dstport")
network_connection_object_mapping = {
    "srcip": {"type": "ip-src", "object_relation": "ip-src"},
    "dstip": {"type": "ip-dst", "object_relation": "ip-dst"},
    "srcport": {"type": "port", "object_relation": "src-port"},
    "dstport": {"type": "port", "object_relation": "dst-port"},
}
pe_object_fields = {
    "entrypoint": {"type": "text", "object_relation": "entrypoint-address"},
    "imphash": {"type": "imphash", "object_relation": "imphash"},
}
pe_object_mapping = {
    "CompanyName": "company-name",
    "FileDescription": "file-description",
    "FileVersion": "file-version",
    "InternalName": "internal-filename",
    "LegalCopyright": "legal-copyright",
    "OriginalFilename": "original-filename",
    "ProductName": "product-filename",
    "ProductVersion": "product-version",
    "Translation": "lang-id",
}
pe_section_object_mapping = {
    "characteristics": {"type": "text", "object_relation": "characteristic"},
    "entropy": {"type": "float", "object_relation": "entropy"},
    "name": {"type": "text", "object_relation": "name"},
    "rawaddr": {"type": "hex", "object_relation": "offset"},
    "rawsize": {"type": "size-in-bytes", "object_relation": "size-in-bytes"},
    "virtaddr": {"type": "hex", "object_relation": "virtual_address"},
    "virtsize": {"type": "size-in-bytes", "object_relation": "virtual_size"},
}
process_object_fields = {
    "cmdline": "command-line",
    "name": "name",
    "parentpid": "parent-pid",
    "pid": "pid",
    "path": "current-directory",
}
protocols = {"tcp": 4, "udp": 4, "icmp": 3, "http": 7, "https": 7, "ftp": 7}
registry_references_mapping = {
    "keyValueCreated": "creates",
    "keyValueModified": "modifies",
}
regkey_object_mapping = {
    "name": {"type": "text", "object_relation": "name"},
    "newdata": {"type": "text", "object_relation": "data"},
    "path": {"type": "regkey", "object_relation": "key"},
}
signerinfo_object_mapping = {
    "sigissuer": {"type": "text", "object_relation": "issuer"},
    "version": {"type": "text", "object_relation": "version"},
}
