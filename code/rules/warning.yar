// Yara rule reference here: https://yara.readthedocs.io/en/stable/writingrules.html

rule warning
{
    meta:
        description = "detects warnings and extraction of the warning content"
        severity = "informational"
        category = "unknown"
    strings: // strings and condition are used to identify either if the dependency manager the rule is for is being used, or if the behavior/leak exists
        $warning = /(WARNING: ([^\r\n])*)/
    condition:
        any of them
}