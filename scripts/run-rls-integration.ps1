$ErrorActionPreference = "Stop"

$projectId = "sparkling-lake-34230002"
$safetyUrl = neon connection-string safety-development-pre-recovery-20260909 --project-id $projectId --role-name dip_app --pooled
$safetyUri = [uri]$safetyUrl.Trim()
$runtimePassword = [uri]::UnescapeDataString(($safetyUri.UserInfo -split ":", 2)[1])

$ownerDirect = (neon connection-string development --project-id $projectId --role-name neondb_owner).Trim()
$ownerPooled = (neon connection-string development --project-id $projectId --role-name neondb_owner --pooled).Trim()
$runtimeBuilder = [System.UriBuilder]$ownerPooled
$runtimeBuilder.UserName = "dip_app"
$runtimeBuilder.Password = $runtimePassword

$env:DIP_RLS_TEST_OWNER_URL = $ownerDirect
$env:DIP_RLS_TEST_DATABASE_URL = $runtimeBuilder.Uri.AbsoluteUri
try {
  node --test --test-reporter=tap test/rls.integration.test.mjs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
  Remove-Item Env:DIP_RLS_TEST_OWNER_URL -ErrorAction SilentlyContinue
  Remove-Item Env:DIP_RLS_TEST_DATABASE_URL -ErrorAction SilentlyContinue
  $runtimePassword = $null
}
