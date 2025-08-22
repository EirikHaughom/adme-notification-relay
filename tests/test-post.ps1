$File = $PSScriptRoot + "osdu-body.json"
@'
[
  {"id":"record_id_1","kind":"kind1","op":"create","recordUpdated":"false"},
  {"id":"record_id_1","kind":"kind1","op":"create","recordUpdated":"true"},
  {"id":"record_id_2","kind":"kind2","op":"delete","deletionType":"soft"},
  {"id":"record_id_3","kind":"kind2","op":"delete","deletionType":"hard"}
]
'@ | Set-Content -NoNewline -Path $File -Encoding UTF8

$secret = $env:HMAC_SECRET; if ([string]::IsNullOrEmpty($secret)) { $secret = "testSecret" }
$bytes  = [IO.File]::ReadAllBytes($File)
$hmac   = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($secret))
$sigHex = -join ($hmac.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })

$response = curl.exe -s -X POST "http://localhost:7071/api/osdu-shim?dryRun=1" `
  -H "Content-Type: application/json" `
  -H "Authorization: hmac $sigHex" `
  --data-binary "@$File"

$response | ConvertFrom-Json | Select-Object -First 1 | ConvertTo-Json -Depth 6