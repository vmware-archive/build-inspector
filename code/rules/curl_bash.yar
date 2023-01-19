// Yara rule reference here: https://yara.readthedocs.io/en/stable/writingrules.html

rule curl_bash
{
    meta:
        description = "Curl bashing is a potentially dangerous practice wherein a script is downloaded using the curl command and then immediately executed on the system via the bash processor. This can lead to supply chain compromise if the targeted script is compromised."
        severity = "major"
        category = "zero_trust"
    strings: // strings and condition are used to identify either if the dependency manager the rule is for is being used, or if the behavior/leak exists
        $curl_bash = /curl .*\| (sudo )?bash/
    condition:
        any of them
}