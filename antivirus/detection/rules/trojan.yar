rule EducationalTrojan {
    meta:
        description = "Educational Trojan heuristic signature"
        category = "Trojan"
    strings:
        $demo = "EDU_TROJAN_PAYLOAD"
        $a = "backdoor_loader"
        $b = "persistence_beacon"
        $c = "remote_payload"
    condition:
        $demo and (2 of ($a, $b, $c))
}
