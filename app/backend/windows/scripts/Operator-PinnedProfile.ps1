# Offline-only Windows OpenVPN AUTLOGIN profile trust check. Expected CA, CN,
# endpoint MUST have independent provenance. Never invoke a VPN or mark TLS live.
function Test-OigPinnedAutologinProfile {
 [CmdletBinding()]
 param(
 [Parameter(Mandatory)][string]$Text,
 [Parameter(Mandatory)][string]$ExpectedHost,
 [Parameter(Mandatory)][ValidateRange(1,65535)][int]$ExpectedPort,
 [Parameter(Mandatory)][ValidateSet('udp','tcp')][string]$ExpectedProtocol,
 [Parameter(Mandatory)][string]$PinnedCaSha256,
 [Parameter(Mandatory)][string]$ExpectedPeerCN
 )
 $deny=[pscustomobject]@{valid=$false;pinnedConstraintsMatch=$false;transportAttempted=$false;serverIdentityVerified=$false;readyForAutomaticConnection=$false}
 if([string]::IsNullOrEmpty($Text) -or $Text.Length -gt 131072 -or
 $Text.IndexOf([char]0) -ge 0 -or $Text -match '[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]'){return $deny}
 if($PinnedCaSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedPeerCN -cnotmatch '^[A-Za-z0-9._-]{1,128}$' -or
 $ExpectedHost -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'){return $deny}
 $s=$Text.Replace([string]::Concat([char]13,[char]10),[string][char]10)
 if($s.Contains([char]13)){return $deny}
 $blocks=@{};$lines=[Collections.Generic.List[string]]::new()
 $current='';$buf=[Collections.Generic.List[string]]::new()
 foreach($raw in ($s -split [char]10)){
  $line=$raw.Trim()
  if($current){
   if($line -ceq ('</'+$current+'>')){
    if($buf.Count -eq 0){return $deny}
    $blocks[$current]=($buf -join [char]10);$buf.Clear();$current=''
   }elseif($line.StartsWith('<')){return $deny}
   else{[void]$buf.Add($line)}
   continue
  }
  if(-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')){continue}
  if($line -match '^<([a-z-]+)>$'){
   $tag=$Matches[1]
   if($tag -notin @('ca','cert','key') -or $blocks.ContainsKey($tag)){return $deny}
   $current=$tag;continue
  }
  if($line.Contains('<') -or $line.Contains('>')){return $deny}
  [void]$lines.Add($line)
 }
 if($current -or $blocks.Count -ne 3){return $deny}
 $allow=@{
 'client'='^client$';'dev'='^dev[ \t]+tun$';'proto'='^proto[ \t]+(udp|tcp|tcp-client)$'
 'remote'='^remote[ \t]+[A-Za-z0-9][A-Za-z0-9.-]{0,252}[ \t]+[0-9]{1,5}$'
 'nobind'='^nobind$';'persist-key'='^persist-key$';'persist-tun'='^persist-tun$'
 'resolv-retry'='^resolv-retry[ \t]+infinite$';'auth-nocache'='^auth-nocache$'
 'cipher'='^cipher[ \t]+AES-(128|256)-GCM$'
 'data-ciphers'='^data-ciphers[ \t]+AES-256-GCM:AES-128-GCM$'
 'auth'='^auth[ \t]+SHA(256|512)$';'verb'='^verb[ \t]+[0-3]$'
 'remote-cert-tls'='^remote-cert-tls[ \t]+server$'
 'verify-x509-name'='^verify-x509-name[ \t]+[A-Za-z0-9._-]{1,128}[ \t]+name$'
 }
 $seen=@{}
 foreach($line in $lines){
  $parts=$line -split '[ \t]+'
  $tok=$parts[0].ToLowerInvariant()
  if(-not $allow.ContainsKey($tok) -or $seen.ContainsKey($tok) -or
   -not [regex]::IsMatch($line,$allow[$tok],[Text.RegularExpressions.RegexOptions]::IgnoreCase)){return $deny}
  $seen[$tok]=$parts
 }
 foreach($k in @('client','dev','proto','remote','remote-cert-tls','verify-x509-name')){
  if(-not $seen.ContainsKey($k)){return $deny}
 }
 $protocol=$seen['proto'][1].ToLowerInvariant()
 if($protocol -eq 'tcp-client'){$protocol='tcp'}
 if($protocol -ne $ExpectedProtocol -or
 -not [string]::Equals($seen['remote'][1],$ExpectedHost,[StringComparison]::OrdinalIgnoreCase) -or
 [int]$seen['remote'][2] -ne $ExpectedPort -or $seen['verify-x509-name'][1] -cne $ExpectedPeerCN){return $deny}
 try{
  $ca=$blocks['ca'].Trim();$cert=$blocks['cert'].Trim();$key=$blocks['key'].Trim()
  if($ca -cnotmatch '(?s)\A-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\z' -or
  $cert -cnotmatch '(?s)\A-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\z' -or
  $key -cnotmatch '(?s)\A-----BEGIN (?<kind>RSA |EC |)PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END \k<kind>PRIVATE KEY-----\z'){return $deny}
  $body=($ca -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s','')
  $der=[Convert]::FromBase64String($body)
  $c=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
  try{
   $caHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($c.RawData)).ToLowerInvariant()
   if($c.RawData.Length -ne $der.Length -or $caHash -cne $PinnedCaSha256){return $deny}
  }finally{$c.Dispose()}
  $body=($cert -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s','')
  $certDer=[Convert]::FromBase64String($body)
  $client=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certDer)
  if($client.RawData.Length -ne $certDer.Length){$client.Dispose();return $deny}
  # Certificate/private-key pairing is verified in memory. A PEM-shaped but
  # unrelated or corrupted key is not a usable AUTLOGIN credential.
  $paired=$false
  $rsa=[Security.Cryptography.RSA]::Create()
  try{
   try{
    $rsa.ImportFromPem($key)
    $bound=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($client,$rsa)
    try{$paired=$true}finally{$bound.Dispose()}
   }catch{}
  }finally{$rsa.Dispose()}
  if(-not $paired){
   $ec=[Security.Cryptography.ECDsa]::Create()
   try{
    try{
     $ec.ImportFromPem($key)
     $bound=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($client,$ec)
     try{$paired=$true}finally{$bound.Dispose()}
    }catch{}
   }finally{$ec.Dispose()}
  }
  $client.Dispose()
  if(-not $paired){return $deny}
 }catch{return $deny}
 return [pscustomobject]@{
  valid=$true;pinnedConstraintsMatch=$true;protocol=$protocol;host=$ExpectedHost;port=$ExpectedPort
  caDerSha256=$caHash;expectedPeerCN=$ExpectedPeerCN
  transportAttempted=$false;serverIdentityVerified=$false;readyForAutomaticConnection=$false
 }
}
