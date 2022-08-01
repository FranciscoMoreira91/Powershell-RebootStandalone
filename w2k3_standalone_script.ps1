#Clear-Host
param(
    [Parameter()]
    [string]
    $username,
    [Parameter()]
    [string]$password,
    [Parameter()]
    [string]$file
)
if($username -eq ""){write-host "Username needed";exit}
if($password -eq ""){write-host "Password needed";exit}
if($file -eq ""){write-host "File needed";exit}
$readfile = Get-Content -Path $file | ConvertFrom-Csv

$pwd = ConvertTo-SecureString $password -AsPlainText -Force

# username convem ter o dominio do ficheiro? dominio\username
$Cred = New-Object System.Management.Automation.PSCredential ($username, $pwd)


foreach ($_ in $readfile){
    try{
        write-host "Connection to: "$_.nodename $_.ip
        $state1 = Invoke-Command -ComputerName $_.ip { Get-Service } -Credential $Cred -ErrorAction STOP
        $time1 = Invoke-Command -ComputerName $_.ip { $Data_Query = Get-WmiObject -Class Win32_OperatingSystem; $Data_Query.ConvertToDateTime($Data_Query.LocalDateTime) - $Data_Query.ConvertToDateTime($Data_Query.LastBootUpTime) } -Credential $Cred -ErrorAction STOP
        # if for case rerun the script/task and the Server have 0 day of boottime the script will skip this server/machine
        if ($time1.Days -eq 0) {"Server {0} is already rebooted" -f $_.nodename;continue}
        $outlog = ".\logs\{0}.{2}.{1}.txt" -f $_.nodename, (Get-Date -format "yyyy-MM-dd"), "before_reboot"
        $state1 | Out-File $outlog
        $time1 | Out-File -Append $outlog
    }
    catch{
        write-host "Username, Password or Target invalid, verify credentials"
        # STOP the program for follow the order reboot or CONTINUE to the next one ? 
        continue
    }
    
    #aqui validar se é cluster else whatever
    $reboot = Restart-Computer -ComputerName $_.ip -Force

    $countexit = 0
    Do {
        write-host "contador:" $countexit
        # -gt (greater then), se for -eq (equal) colocar depois do $countexit++
        if ($countexit -gt 6){
            $rowdiff = "{0} ({1}) {2} - Failed to boot up (reboot via powershell script)" -f $_.nodename, $_.ip, $_.domain
            Write-EventLog -LogName Application -Source EventSystem -EntryType Error -EventId 512 -Message $rowdiff
            # if the X time waiting it's > 6 (6* x time) they will looping to next server/line
            continue
        }
        Write-Output "Waiting server boots up."
        # 120 sec, 6 retry max -> else exit ^ with create log
        Start-Sleep -s 15
        
    try{
        $uptime = Invoke-Command -ComputerName $_.ip { $Data_Query = Get-WmiObject -Class Win32_OperatingSystem; $Data_Query.ConvertToDateTime($Data_Query.LocalDateTime) - $Data_Query.ConvertToDateTime($Data_Query.LastBootUpTime) } -Credential $Cred -ErrorAction STOP
        }
    catch{
        write-host "Waiting server boots up..."
        #nothing to do, just checking if server is reboot successfuly
        }
        # incrementar a variavel de contar
        $countexit++
    }
    Until ($uptime.Days -eq 0)

    write "restarted"
    Start-Sleep -s 5
    # 5 min sleep = 300 seconds
    #read-host “Press ENTER to continue...”
    
    try {
        $state2 = Invoke-Command -ComputerName $_.ip { Get-Service } -Credential $Cred -ErrorAction STOP
        $time2 = Invoke-Command -ComputerName $_.ip { $Data_Query = Get-WmiObject -Class Win32_OperatingSystem; $Data_Query.ConvertToDateTime($Data_Query.LocalDateTime) - $Data_Query.ConvertToDateTime($Data_Query.LastBootUpTime) } -Credential $Cred -ErrorAction STOP
        $outlog = ".\logs\{0}.{2}.{1}.txt" -f $_.nodename, (Get-Date -format "yyyy-MM-dd"), "after_reboot"
        $state2 | Out-File $outlog
        $time2 | Out-File -Append $outlog
        # Status   Name               DisplayName                            PSComputerName
        foreach ($x in $state1){
            foreach ($y in $state2){
                if ($x.Name -eq $y.Name){
                    if($x.Status -ne $y.Status){
                        $rowdiff = "Server:`n{4} IP-Address:`n{5} Domain:`n{6}`n{0} : {3}  Service Status:`nAfter: {1} `nBefore: {2}" -f $x.Name ,$x.Status,$y.Status, $x.DisplayName, $_.nodename, $_.ip, $_.domain
                        Write-EventLog -LogName Application -Source EventSystem -EntryType Error -EventId 512 -Message $rowdiff
                        $rowdiff
                    }
                }
            }
        }    
    }
    catch {
        $rebooterror = "Server: {0}`n IP-Address: {1}`n Domain: {2}`nError on Get-Services After Reboot" -f $_.nodename, $_.ip, $_.domain
        $rebooterror
        continue
    }
# end file looping
}