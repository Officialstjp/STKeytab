# Module-wide constants and simple maps
# Loaded first (00.*) so later functions can safely reference them under Set-StrictMode.

# Kerberos principal name types used by the keytab writer and principal helpers
$script:NameTypes = @{
  KRB_NT_PRINCIPAL = 1  # Named user or krbtgt principal
  KRB_NT_SRV_HST   = 3  # Service with host name as instance (e.g., host/fqdn)
}

# Coarse classification for special/high-impact principals
$script:HighImpactPrincipals = @{ 'KRBTGT' = $true }
