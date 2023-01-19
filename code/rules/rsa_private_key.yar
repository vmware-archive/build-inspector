// Yara rule reference here: https://yara.readthedocs.io/en/stable/writingrules.html

rule rsa_private_key
{
    meta:
        description = "Private keys should never be exposed"
        severity = "major"
        category = "zero_trust"
    strings: 
        $content = /-----BEGIN( RSA |\s)PRIVATE KEY-----/
    condition:
        any of them
}