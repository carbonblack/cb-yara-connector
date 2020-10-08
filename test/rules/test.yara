rule test
{
    meta:
        author = "VMware Carbon Black (http://carbonblack.com/resources/support)"
        date = "2015/08"
        filetype = "exe"
        testing = "yep"

    strings:
        $a = "win8_rtm.120725-1247"

    condition:
        all of them
}
