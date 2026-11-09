# Side-effect-free input policy for public VPN Gate profiles.
# Import by dot-source; a downloaded .ovpn file is never PowerShell code.
function Test-OigVpnProfile {
 param(
   [Parameter(Mandatory)][string]$Text,
   [Parameter(Mandatory)][string]$ExpectedIP,
   [Parameter(Mandatory)][int]$ExpectedPort,
   [Parameter(Mandatory)][ValidateSet('udp','tcp')][string]$ExpectedProtocol
 )
 if($Text.Length -gt 131072 -or $Text.Contains([char]0)){return $false}
 if($ExpectedPort -lt 1 -or $ExpectedPort -gt 65535){return $false}
 $s=$Text.Replace([string]::Concat([char]13,[char]10),[string][char]10).Replace([string][char]13,[string][char]10)
 $tagMatches=[regex]::Matches($s,'(?m)^[ \t]*<(/?[A-Za-z][A-Za-z0-9_-]*)>[ \t]*$')
 $tags=@('ca','/ca','cert','/cert','key','/key')
 if($tagMatches.Count -ne $tags.Count){return $false}
 for($i=0;$i -lt $tags.Count;$i++){
   if($tagMatches[$i].Groups[1].Value -cne $tags[$i]){return $false}
 }
 foreach($tag in @('ca','cert','key')){
   $m=[regex]::Match($s,"(?ms)^[ \t]*<$tag>[ \t]*\n(.*?)^[ \t]*</$tag>[ \t]*$")
   if(-not $m.Success){return $false}
   $pem=$m.Groups[1].Value.Trim()
   $kind=if($tag -eq 'key'){'(RSA PRIVATE KEY|PRIVATE KEY)'}else{'(CERTIFICATE)'}
   if(-not [regex]::IsMatch($pem,"\A-----BEGIN $kind-----\n[A-Za-z0-9+/=\n]+-----END $kind-----\z")){return $false}
 }
 $withoutPem=[regex]::Replace($s,'(?ms)^[ \t]*<(ca|cert|key)>[ \t]*\n.*?^[ \t]*</\1>[ \t]*$','')
 $allowed=@{
  'dev'='^dev[ \t]+tun$'
  'proto'='^proto[ \t]+(udp|tcp)$'
  'remote'='^remote[ \t]+([0-9]{1,3}\.){3}[0-9]{1,3}[ \t]+[0-9]{1,5}$'
  'cipher'='^cipher[ \t]+AES-128-CBC$'
  'data-ciphers'='^data-ciphers[ \t]+AES-128-CBC$'
  'auth'='^auth[ \t]+SHA1$'
  'resolv-retry'='^resolv-retry[ \t]+infinite$'
  'nobind'='^nobind$'
  'persist-key'='^persist-key$'
  'persist-tun'='^persist-tun$'
  'client'='^client$'
  'verb'='^verb[ \t]+3$'
 }
 $found=@{}
 $remote=$null
 foreach($line in ($withoutPem -split [char]10)){
   $value=$line.Trim()
   if($value.Length -eq 0 -or $value.StartsWith('#') -or $value.StartsWith(';')){continue}
   $token=($value -split '[ \t]+',2)[0].ToLowerInvariant()
   if(-not $allowed.ContainsKey($token) -or $found.ContainsKey($token)){return $false}
   if(-not [regex]::IsMatch($value,$allowed[$token],[Text.RegularExpressions.RegexOptions]::IgnoreCase)){return $false}
   $found[$token]=$true
   if($token -eq 'remote'){$remote=$value}
   if($token -eq 'proto'){
     if(($value -split '[ \t]+')[1].ToLowerInvariant() -ne $ExpectedProtocol){return $false}
   }
 }
 if($found.Count -ne $allowed.Count -or $null -eq $remote){return $false}
 $parts=$remote -split '[ \t]+'
 $ip=$null
 if(-not [Net.IPAddress]::TryParse([string]$parts[1],[ref]$ip)){return $false}
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
 return ($ip.ToString() -eq $ExpectedIP -and [int]$parts[2] -eq $ExpectedPort)
}

# A previously successful public relay may not silently rotate its embedded
# CA at the SAME IP:port. This is continuity/TOFU, NOT independent identity
# authentication. The first profile's CA still comes from an external directory.
function Get-OigVpnProfileCaSha256 {
 param([string]$Text)
 if([string]::IsNullOrWhiteSpace($Text) -or $Text.Length -gt 131072){return ''}
 # Match the existing profile policy's newline normalization: real VPN Gate
 # public profiles are CRLF and can include blank lines before </ca>.
 $normalized=$Text.Replace([string]::Concat([char]13,[char]10),[string][char]10).Replace([string][char]13,[string][char]10)
 $matches=[regex]::Matches($normalized,'(?ms)^[ \t]*<ca>[ \t]*\n(.*?)^[ \t]*</ca>[ \t]*$')
 if($matches.Count -ne 1){return ''}
 $pem=$matches[0].Groups[1].Value.Trim()
 if(-not [regex]::IsMatch($pem,'\A-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\z')){return ''}
 try{
   $payload=($pem -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s','')
   $der=[Convert]::FromBase64String($payload)
   $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
   try{
     if($cert.RawData.Length -ne $der.Length){return ''}
     return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($cert.RawData)).ToLowerInvariant()
   }finally{$cert.Dispose()}
 }catch{return ''}
}

function Test-OigKnownRelayCaContinuity {
 param(
   [Parameter(Mandatory)][string]$IP,
   [Parameter(Mandatory)][int]$Port,
   [Parameter(Mandatory)][string]$ProfileSha256,
   [Parameter(Mandatory)][string]$CaSha256,
   [Parameter(Mandatory)][hashtable]$KnownSuccesses
 )
 if($IP -notmatch '^[0-9.]+$' -or $Port -lt 1 -or $Port -gt 65535){return $false}
 if($ProfileSha256 -notmatch '^[a-fA-F0-9]{64}$' -or $CaSha256 -notmatch '^[a-fA-F0-9]{64}$'){return $false}
 foreach($key in @($KnownSuccesses.Keys)){
   $item=$KnownSuccesses[$key]
   if($null -eq $item){continue}
   if(([string]$item.ip) -ne $IP -or ([string]$item.port) -ne ([string]$Port)){continue}
   $oldPin=([string]$item.caSha256).ToLowerInvariant()
   if($oldPin -match '^[a-f0-9]{64}$' -and $oldPin -eq $CaSha256.ToLowerInvariant()){continue}
   # Legacy success rows predate CA pins. The exact same profile digest can
   # reconnect, but a *changed* profile at that endpoint must be denied.
   if($oldPin -eq '' -and ([string]$key).ToLowerInvariant() -eq $ProfileSha256.ToLowerInvariant()){continue}
   return $false
 }
 return $true
}
