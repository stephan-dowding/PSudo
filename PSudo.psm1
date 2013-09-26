$Win32LogonMethods = @' 
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(
    string lpszUsername, 
    string lpszDomain, 
    string lpszPassword, 
    int dwLogonType, 
    int dwLogonProvider, 
    out IntPtr phToken
    ); 
    
[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern int DuplicateToken( IntPtr hToken,
    int impersonationLevel,
    ref IntPtr hNewToken);
 
[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool RevertToSelf();
 
[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern bool CloseHandle(IntPtr handle);
'@

$type = Add-Type -MemberDefinition $Win32LogonMethods -Name Win32Utils -Namespace PSudo -PassThru 
$LOGON32_LOGON_INTERACTIVE = 2
$LOGON32_PROVIDER_DEFAULT = 0
$SECURITY_IMPERSONATION = 2

function PSudo
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=1)][string]$domain,
        [Parameter(Position=1,Mandatory=1)][string]$username,
        [Parameter(Position=2,Mandatory=1)][string]$password,
        [Parameter(Position=3,Mandatory=1)][scriptblock]$cmd
    )
    
    $token = [IntPtr]::Zero
    $tokenDuplicate = [IntPtr]::Zero
    $impersonationContext = $NULL
    
    try
    {
        if ( $type::RevertToSelf() )
        {
            if ($type::LogonUser(
				$username, 
                $domain, 
				$password, 
				$LOGON32_LOGON_INTERACTIVE,
				$LOGON32_PROVIDER_DEFAULT, 
				[ref] $token ) -ne 0 )
            {
                if ($type::DuplicateToken( 
                    $token,
                    $SECURITY_IMPERSONATION,
                    [ref] $tokenDuplicate ) -ne 0 )
				{
					$impersonationContext = [System.Security.Principal.WindowsIdentity]::Impersonate( $tokenDuplicate )
				} else {
                    throw New-Object System.ComponentModel.Win32Exception @([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
                }
            } else {
                throw New-Object System.ComponentModel.Win32Exception @([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        } else {
            throw New-Object System.ComponentModel.Win32Exception @([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
    
        Write-Output "***** Impersonating $username *****"
        & $cmd
        Write-Output "***** Undoing Impersonation *****"
    } finally {
        if ( $token -ne [IntPtr]::Zero )
		{
			$type::CloseHandle($token) | Out-Null
		}
		if ( $tokenDuplicate -ne [IntPtr]::Zero )
		{
			$type::CloseHandle($tokenDuplicate) | Out-Null
		}
        if ( $impersonationContext -ne $NULL )
        {
            $impersonationContext.Undo()
        }
    }
}

export-modulemember -function PSudo