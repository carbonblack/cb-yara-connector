rule test
{
    meta:
        author = "Bit9 + Carbon Black <dev-support@bit9.com>"
        date = "2015/08"
        filetype = "exe"
        testing = "yep"

    strings:
        $a = "win8_rtm.120725-1247"

    condition:
        all of them
}

