rule EducationalRansomware {
    meta:
        description = "Educational ransomware heuristic signature"
        category = "Ransomware"
    strings:
        $a = "EDU_RANSOMWARE_PAYLOAD"
        $b = "encrypt_all_files"
        $c = "ransom_note"
    condition:
        2 of ($a, $b, $c)
}
