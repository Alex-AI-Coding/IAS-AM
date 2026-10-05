rule WormSignature_NetworkReplication
{
    meta:
        description = "Educational detection for worm-like network replication patterns"
        category = "Worm"
        severity = "high"
    strings:
        $demo = "EDU_WORM_PAYLOAD"
        $replication1 = "CreateRemoteThread" nocase
        $replication2 = "WMI_PROCESS_CREATE" nocase
        $replication3 = "IpSendArp" nocase
        $network = "bind" nocase
    condition:
        $demo and (any of ($replication*) and $network)
}

rule WormSignature_FileReplication
{
    meta:
        description = "Educational detection for worm file copying behavior"
        category = "Worm"
        severity = "high"
    strings:
        $demo = "EDU_WORM_PAYLOAD"
        $copy1 = "CopyFileA" nocase
        $copy2 = "CopyFileW" nocase
        $system_dir = "System32" nocase
    condition:
        $demo and (any of ($copy*) and $system_dir)
}

rule WormSignature_MassEmailer
{
    meta:
        description = "Educational detection for mass email propagation"
        category = "Worm"
        severity = "medium"
    strings:
        $demo = "EDU_WORM_PAYLOAD"
        $smtp = "SMTP" nocase
        $mail = "SendMailA" nocase
        $outlook = "Outlook" nocase
        $address_book = "AddressBook" nocase
    condition:
        $demo and ($smtp and 1 of ($mail, $outlook, $address_book))
}
