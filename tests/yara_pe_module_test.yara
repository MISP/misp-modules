import "pe"
rule my_pe {
    condition:
        pe.imphash() == "eecc824da5b175f530705611127a6b41"
}
