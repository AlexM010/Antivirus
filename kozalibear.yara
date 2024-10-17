rule KozaliBear_ransomware : ransomware {
    meta:
        description = "YARA rule to detect the KozaliBear ransomware"
        author = "Alexandros Markodimitrakis"
        threat_level=3
        in_the_wild=true
    strings:
        $bitcoin_wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $virus_signature = { 98 1D 00 00 EC 33 FF FF FB 06 00 00 00 46 0E 10 }
        $locked_file_extension = ".locked"
    condition:
        $bitcoin_wallet or $virus_signature or $locked_file_extension
}
