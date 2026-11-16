# Synthetic records with the property order and Export-Csv settings of ADTimeline
# fa570aa15a03614b8dd1ea956abb556f47f4f453, ADTimeline.ps1 metadata loop.
$rows = @()
foreach ($attribute in @('nTSecurityDescriptor', 'member', 'altRecipient')) {
    $linked = $attribute -ne 'nTSecurityDescriptor'
    $rows += [pscustomobject][ordered]@{
        ftimeLastOriginatingChange = '2026-01-02T03:04:05Z'
        Name = 'Synthetic; "group"'
        pszAttributeName = $attribute
        ObjectClass = $(if ($attribute -eq 'altRecipient') { 'user' } else { 'group' })
        DN = 'CN=Synthetic,OU=Lab,DC=example,DC=test'
        ObjectCategory = 'CN=Group,CN=Schema,CN=Configuration,DC=example,DC=test'
        SamAccountName = 'synthetic'
        dwVersion = '3'
        WhenCreated = '2025-01-01 00:00:00Z'
        Member = $(if ($linked) { 'CN=Target,DC=example,DC=test' } else { '' })
        ftimeCreated = $(if ($linked) { '2026-01-01T00:00:00Z' } else { '' })
        ftimeDeleted = $(if ($attribute -eq 'member') { '2026-01-02T03:04:05Z' } elseif ($linked) { '1601-01-01T00:00:00Z' } else { '' })
        SID = 'S-1-5-21-111-222-333-1001'
        pszLastOriginatingDsaDN = 'CN=NTDS Settings,CN=DC01,CN=Servers,CN=Lab,CN=Sites,CN=Configuration,DC=example,DC=test'
        uuidLastOriginatingDsaInvocationID = '9a0448b4-8451-40c3-8bcd-9c878ae3309c'
        usnOriginatingChange = '18446744073709551610'
        usnLocalChange = '9007199254740993'
    }
}
$rows | Sort-Object -Property ftimeLastOriginatingChange | Export-Csv /fixtures/timeline_example.test.csv -Delimiter ';' -NoTypeInformation -Encoding utf8BOM
