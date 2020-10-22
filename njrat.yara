rule njRAT: Remote Access Trojan
{
    meta:
        description = "njRAT - Remote Access Trojan"
        author = "Bruno Jin Nakagawa"
	Date = "22.10.2020"
	reference = "https://any.run/malware-trends/njrat"
	hash1 = "8de7e0127a334d8fc04e3babe916303e8a528efd3e7a00899b46bcaf5ff30157"
	hash2 = "6dc46fc7dd961e304f973caf2a1787e084fa44acbcc0e946f668d5d36c0dd38b"
	hash3 = "6e273cd6308ca834116f6a57642e367065d5c166cd845729cfb67c5ac6b4c21b"
	hash4 = "78989c1debf987247e405bfb9faac1072785b232c453e3cc8a3ea5afa371c1d2"

    strings:
        $str1 = "FromBase64String" nocase
        $str2 = "Base64String" nocase
        $str3 = "Send" nocase
        $str4 = "DownloadData" nocase
        $str5 = "DeleteSubKey" nocase
        $str6 = "get_MachineName" nocase
        $str7 = "get_UserName" nocase
        $str8 = "get_LastWriteTime" nocase
        $str9 = "GetVolumeInformation" nocase
        $str10 = "OSFullName" nocase
        $str11 = "Stub.exe"
        $str12 = "w.exe"
        $str13 = "k.exe"

    condition:
        11 of them
}

