rule EducationalSuspicious
{
    meta:
        description = "Educational low-risk, potentially unwanted software signature"
        category = "Potentially unwanted"
        severity = "low"
    strings:
        $marker = "EDU_SUSPICIOUS_PAYLOAD"
        $toolbar = "optional_toolbar" nocase
        $telemetry = "telemetry_prompt" nocase
    condition:
        $marker and 1 of ($toolbar, $telemetry)
}

rule EducationalAdware
{
    meta:
        description = "Educational low-risk advertising software signature"
        category = "Potentially unwanted"
        severity = "low"
    strings:
        $marker = "EDU_ADWARE_PAYLOAD"
        $offer = "optional_offer" nocase
        $notification = "sponsored_notification" nocase
    condition:
        $marker and 1 of ($offer, $notification)
}
