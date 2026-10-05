rule SpywareSignature_KeyLogger
{
    meta:
        description = "Educational detection for keylogging behavior"
        category = "Spyware"
        severity = "high"
    strings:
        $hook1 = "SetWindowsHookExA" nocase
        $hook2 = "SetWindowsHookExW" nocase
        $getkey = "GetKeyState" nocase
        $keydown = "WM_KEYDOWN" nocase
    condition:
        2 of ($hook*, $getkey, $keydown)
}

rule SpywareSignature_ScreenCapture
{
    meta:
        description = "Educational detection for screen capture/monitoring"
        category = "Spyware"
        severity = "high"
    strings:
        $getdc = "GetDC" nocase
        $bitblt = "BitBlt" nocase
        $screenshot = "Screenshot" nocase
        $screen_capture = "ScreenCapture" nocase
    condition:
        2 of them
}

rule SpywareSignature_DataThief
{
    meta:
        description = "Educational detection for data theft indicators"
        category = "Spyware"
        severity = "high"
    strings:
        $browser_theft = "Cookie" nocase
        $password_theft = "Password" nocase
        $clipboard = "Clipboard" nocase
        $email_theft = "Email" nocase
    condition:
        3 of them and filesize < 5MB
}

rule SpywareSignature_RemoteAccess
{
    meta:
        description = "Educational detection for remote access/backdoor patterns"
        category = "Spyware"
        severity = "high"
    strings:
        $listening = "bind" nocase
        $cmd_shell = "cmd.exe" nocase
        $remote = "Remote" nocase
    condition:
        $listening and $cmd_shell and $remote
}
