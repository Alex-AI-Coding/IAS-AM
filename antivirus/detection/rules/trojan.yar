rule EducationalTrojan {
    meta:
        description = "Educational Trojan heuristic signature"
        category = "Trojan"
    strings:
        $a = "backdoor_loader"
        $b = "persistence_beacon"
        $c = "remote_payload"
    condition:
        2 of ($a, $b, $c)
}
