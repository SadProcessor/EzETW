## EzETW
# Get-EzEventFilter
# Get-EzEvent
# Get-EZEventTracer

<#
.Synopsis
   Get-EzEventFilter
.DESCRIPTION
   Easy Event Filter
.EXAMPLE
   EzFilter -Start (Get-Date).addHours(-12) -End (Get-Date) | fl
.EXAMPLE
   EzFilter -Xpath -Start (Get-Date).addHours(-12) -End (Get-Date) -Provider 'Microsoft-Windows-PowerShell' -level Verbose
.EXAMPLE
   EzFilter -MDE -Ago 1d -DataSource DeviceEvents
.EXAMPLE
   EzFilter -Sentinel -Start (Get-Date).addHours(-12) -End (Get-Date) -DataSource Sysmon -Where 'EventID == 10'
#>
function Get-EzEventFilter{
    [CmdletBinding(DefaultParameterSetName='Mix')]
    [Alias('EzFilter')]
    Param(
        [Parameter(Mandatory=0,ParameterSetName='Sentinel')]
        [Parameter(Mandatory=0,ParameterSetName='MDE')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')]
        [Parameter(Mandatory=0,ParameterSetName='Mix')][DateTime]$Start,
        [Parameter(Mandatory=0,ParameterSetName='Sentinel')]
        [Parameter(Mandatory=0,ParameterSetName='MDE')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')]
        [Parameter(Mandatory=0,ParameterSetName='Mix')][DateTime]$End,
        [Parameter(Mandatory=1,ParameterSetName='SentinelAgo')]
        [Parameter(Mandatory=1,ParameterSetName='MDEAgo')][String]$Ago,
        [Parameter(Mandatory=1,ParameterSetName='XPath')][SWitch]$XPath,
        [Parameter(Mandatory=1,ParameterSetName='MDEAgo')]
        [Parameter(Mandatory=1,ParameterSetName='MDE')][SWitch]$MDE,
        [Parameter(Mandatory=1,ParameterSetName='SentinelAgo')]
        [Parameter(Mandatory=1,ParameterSetName='Sentinel')][SWitch]$Sentinel,
        [Parameter(Mandatory=0,ParameterSetName='XPath')][String[]]$Provider,
        [ValidateSet('Critical','Error','Warning','Info','Verbose')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')][String]$Level,
        [Parameter(Mandatory=0,ParameterSetName='SentinelAgo')]
        [Parameter(Mandatory=0,ParameterSetName='MDEAgo')]
        [Parameter(Mandatory=0,ParameterSetName='Sentinel')]
        [Parameter(Mandatory=0,ParameterSetName='MDE')][String]$DataSource='<UNKNOWN DATA SOURCE>',
        [Parameter(Mandatory=0,ParameterSetName='SentinelAgo')]
        [Parameter(Mandatory=0,ParameterSetName='MDEAgo')]
        [Parameter(Mandatory=0,ParameterSetName='Sentinel')]
        [Parameter(Mandatory=0,ParameterSetName='MDE')][String[]]$Where
        )
    ## PREP
    # ParameterSetName
    $SetName = $PSCmdlet.ParameterSetName
    # Start UTC
    if(-Not$Start){$Start=Get-Date}
    $Start = $Start.ToUniversalTime()
    $StartXml = [Xml.XmlConvert]::ToString($Start).Split('.')[0]
    # Stop UTC
    if($End){
        $End = $End.ToUniversalTime()
        $EndXml = [Xml.XmlConvert]::ToString($End).Split('.')[0]
        }
    # Level
    if($Level){$Lvl = Switch($Level){
        Verbose  {5}
        Info     {4}
        Warning  {3}
        Error    {2}
        Critical {1}
        }}
    ## FILTERS
    # XPath Filter
    if($SetName -match "Mix|XPath"){
        [Collections.ArrayList]$FltrBlck = @()
        # Time
        $TimeFltr = if(-Not$End){"System/TimeCreated[@SystemTime > '${StartXml}Z']"}
                    else{"System/TimeCreated[@SystemTime > '${StartXml}Z' and @SystemTime < '${EndXml}Z']"}
        $Null = $FltrBlck.add($TimeFltr)
        # Provider
        if($Provider){[Collections.ArrayList]$ProvBlck = @()
            Foreach($ProvName in $Provider){$Null=$ProvBlck.Add("@Name='$ProvName'")}
            $Null = $FltrBlck.add("System/Provider[$($ProvBlck -join ' or ')]")
            }
        # Level
        if($Level){$Null = $FltrBlck.add("System/Level<=$Lvl")}
        # XpathFltr
        $XPathFltr = '*['+ ($FltrBlck -join ' and ')+']'
        }
    # KQL Filter
    if($SetName -match "Mix|MDE|Sentinel"){
        if($Where){$WhrBlck = "`r`n| where " + $(($Where)-join "`r`n| where ")}
        #[Collections.ArrayList]$KQLBlck = @()
        # If Ago
        if($SetName -match "Ago"){
            # Ago: MDE Filter
            if($SetName -match 'MDE'){
                $MDEAgoFltr = "let TimeFrame = $Ago;`r`n$DataSource`r`n| where Timestamp > ago(TimeFrame)$WhrBlck"
                }
            # Ago: Sentinel Filter
            if($SetName -match 'Sentinel'){
                $SentinelAgoFltr = "let TimeFrame = $Ago;`r`n$DataSource`r`n| where TimeGenerated > ago(TimeFrame)$WhrBlck"
                }}
        # If Start/End (=Not Ago)
        else{
            if($SetName -eq 'Mix'){
                $MDEFltr = if($End){"| where datetime(${StartXml}Z) <= Timestamp and Timestamp <= datetime(${EndXml}Z)$WhrBlck"}else{"| where Timestamp >= datetime(${StartXml}Z)$WhrBlck"}
                $SentinelFltr = if($End){"| where datetime(${StartXml}Z) <= TimeGenerated and TimeGenerated <= datetime(${EndXml}Z)$WhrBlck"}else{"| where TimeGenerated >= datetime(${StartXml}Z)$WhrBlck"}
                }
            if($SetName -eq 'MDE'){
                $MDEFltr = if($End){"let StartTime = datetime(${StartXML}Z);`r`nlet EndTime   = datetime(${EndXML}Z);`r`n$DataSource`r`n| where StartTime <= Timestamp and Timestamp <= EndTime$WhrBlck"}
                else{"let StartTime = datetime(${StartXML}Z);`r`n$DataSource`r`n| where StartTime <= Timestamp$WhrBlck"}
                }
            if($SetName -eq 'Sentinel'){
                $SentinelFltr = if($End){"let StartTime = datetime(${StartXML}Z);`r`nlet EndTime   = datetime(${EndXML}Z);`r`n$DataSource`r`n| where StartTime <= TimeGenerated and TimeGenerated <= EndTime$WhrBlck"}
                else{"let StartTime = datetime(${StartXML}Z);`r`n$DataSource`r`n| where StartTime <= TimeGenerated$WhrBlck"}
                }}}
    # OUTPUT
    Switch($SetName){
        Mix{[PSCustomObject]@{XPath=$XPathFltr;MDE=$MDEFltr;Sentinel=$SentinelFltr}}
        Default{Get-Variable -Name "${SetName}fltr" -ValueOnly}
        }}
#####End


###########################################################################################


<#
.Synopsis
   Get-EzEvent
.DESCRIPTION
   Eazy Event Finder
.EXAMPLE
   ezevent -log application -XPath * -Max 200 -ExcludeID 123 -match policy
.EXAMPLE
   $XFilter | EzEvent -LocalFile ./trace.etl
.EXAMPLE
   EzEvent -listLog -ShowEmpty
.EXAMPLE
   EzEvent -ListProvider -Match Malware
.EXAMPLE
   EzEvent -ListEvent -Provider Microsoft-Windows-PowerShell
#>
Function Get-EzEvent{
    [CmdletBinding(DefaultParameterSetName='XPath')]
    [Alias('EzEvent')]
    Param(
        [Parameter(Mandatory=0,ParameterSetName='File',ValueFromPipeline=1)]
        [Parameter(Mandatory=0,ParameterSetName='XPath',ValueFromPipeline=1)][String[]]$XPath='*',
        [Parameter(Mandatory=1,ParameterSetName='File')][String]$LocalFile,
        [Parameter(Mandatory=1,ParameterSetName='Log')][Switch]$ListLog,
        [Parameter(Mandatory=1,ParameterSetName='Provider')][Switch]$ListProvider,
        [Parameter(Mandatory=1,ParameterSetName='EventID')][Switch]$ListEvent,
        [Parameter(Mandatory=1,ParameterSetName='EventID')][String[]]$Provider,
        [Parameter(Mandatory=0,ParameterSetName='XPath')][String[]]$Log='Windows PowerShell',
        [Parameter(Mandatory=0,ParameterSetName='File')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')][Int]$Max,
        [Parameter(Mandatory=0,ParameterSetName='EventID')]
        [Parameter(Mandatory=0,ParameterSetName='File')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')][Int[]]$ExcludeID,
        [Parameter(Mandatory=0,ParameterSetName='Log')][Switch]$ShowEmpty,
        [Parameter(Mandatory=0,ParameterSetName='EventID')][String]$Level,
        [Parameter(Mandatory=0,ParameterSetName='EventID')]
        [Parameter(Mandatory=0,ParameterSetName='Provider')]
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')]
        [Parameter(Mandatory=0,ParameterSetName='XPath')][String[]]$Match,
        [Parameter(Mandatory=0,ParameterSetName='Provider')]
        [Parameter(Mandatory=0,ParameterSetName='Log')][Switch]$AsObject,
        [Parameter(Mandatory=0,ParameterSetName='EventID')][Switch]$Full
        )
    Begin{$SetName = $PSCmdlet.ParameterSetName}
    Process{
        # Get Events
        if($SetName -match 'Xpath|File'){Foreach($Xfilter in $Xpath){
            $Prm = @{}
            if($Max){$Prm.MaxEvents = $Max}
            if($SetName -eq 'XPath'){
                $Output = Foreach($LogName in $Log){
                    $Prm.LogName = $LogName
                    Get-WinEvent -FilterXPath $XFilter @Prm -Oldest
                    }}
            if($SetName -eq 'File'){
                $Prm.Path = $LocalFile
                $Output = Get-WinEvent -FilterXPath $XFilter @Prm -Oldest
                }
            if($ExcludeID){$Output = $Output | Where id -notin $ExcludeID}
            if($Match){Foreach($Rgx in $Match){$Output = $Output | Where Message -match $Rgx}}
            Return $Output
            }}
        ## ListLog
        if($SetName -eq 'Log'){
            # List All
            $output = get-winevent -ListLog * -ea 0
            # Remove Empty
            if(-Not$ShowEmpty){$output = $output | Where RecordCount}
            # Match
            if($Match){Foreach($Rgx in $Match){$Output = $Output | Where LogName -match $Rgx}}
            # Output
            if($AsObject){return $output}Else{Return $output.LogName}
            }
        ## List Provider
        if($SetName -eq 'Provider'){
            # List All
            $Output = Get-WinEvent -ListProvider * -ea 0
            # Match
            if($Match){Foreach($Rgx in $Match){$Output = $Output | Where ProviderName -match $Rgx}}
            # Output
            if($AsObject){Return $Output}Else{$Output.name}
            }
        if($SetName -eq 'EventID'){
            $Output = foreach($Prov in $Provider){Get-WinEvent -ListProvider $Prov -ea 0 | select -expand events <#add calculated prop for prov#>}
            if($ExcludeID){$Output = $Output | Where id -notin $ExcludeID}
            if($Level){$Output = $Output | Where {$_.Level.DisplayName -match $Level}}
            if(-Not$Full){
                $Output = $output|%{[PSCustomObject]@{id=$_.id; Level = $_.Level.DisplayName; Description=$_.Description}}
                if($Match){Foreach($Rgx in $Match){$Output = $Output | Where Description -match $Rgx}}
                }
            Return $Output
            }}
    End{}###
    }
#End


###########################################################################################


<#
.Synopsis
   Invoke-EzTracer
.DESCRIPTION
   Easy Event Tracing
.EXAMPLE
   EzTracer -KeepTrace
.EXAMPLE
   EzTracer -Command {Get-Date} -Snooze 5 -FromLog
#>
function Invoke-EzEventTracer{
    [CmdletBinding(DefaultParameterSetName='File')]
    [Alias('EzTracer')]
    Param(
        [Parameter(Mandatory=0,Position=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,Position=0,ParameterSetName='File')][ScriptBlock[]]$Command={Read-Host ":. Event Trace in Progress :: Press [ENTER] to stop ."},
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')][Int]$Snooze,
        [Parameter(Mandatory=1,ParameterSetName='Log')][Switch]$FromLog,
        [Parameter(Mandatory=0,ParameterSetName='Log')][String[]]$Log='*',
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')][String[]]$Provider='Microsoft-Windows-PowerShell',
        [ValidateSet('Critical','Error','Warning','Info','Verbose')]
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')][String]$Level='Info',
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')][Int[]]$ExcludeID,
        [Parameter(Mandatory=0,ParameterSetName='Log')]
        [Parameter(Mandatory=0,ParameterSetName='File')][String]$Prefix='EzTrace',
        [Parameter(Mandatory=0,ParameterSetName='File')][Switch]$KeepTrace
        )
    # Prep Vars
    $SetName = $PSCmdlet.ParameterSetName
    Foreach($ScriptBlock in $Command){
        ## Prep Vars
        $Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss")
        $TS =  "${Prefix}_$Stamp"
        if($SetName -eq 'File'){
            $LFP = "$pwd\$TS.etl"
            ## Provider to GUID
            $GUIDList = foreach($Prov in $Provider){(Get-WinEvent -ListProvider $Prov | select -expand id).guid}
            ## Start Session
            $Null = Start-EtwTraceSession -Name $TS -LocalFilePath $LFP -RealTime
            ## For each Provider
            foreach($GUID in $GUIDList){$Null = Add-EtwTraceProvider -SessionName $TS -Guid "{$GUID}"}
            }
        ## Start Time
        $Start = (Get-Date).ToUniversalTime().AddSeconds(1)
        Start-Sleep -Milliseconds '1337'
        ## Run Command
        $Result = Invoke-Command -ScriptBlock $ScriptBlock
        ## Snooze
        Start-Sleep -second 1
        if($Snooze){Start-Sleep -Seconds $Snooze}
        ## Stop Session
        if($SetName -eq 'File'){$Null = Stop-EtwTraceSession $TS}
        ## EndTime
        $End = (Get-Date).ToUniversalTime()
        ## Filters
        $XFilter = EzFilter -XPath -Start $Start -End $End -Provider $Provider -Level $Level
        $MDEFilter = EZFilter -MDE -Start $Start -End $End
        $SentinelFilter = EzFilter -Sentinel -Start $Start -End $End
        ## Events
        if($SetName  -eq 'Log'){$Evt = EzEvent -XPath $XFilter -ea 0}
        if($SetName -eq 'File'){$Evt = EzEvent -XPath $XFilter -LocalFile $LFP -ea 0}
        ## Remove Trace
        if($SetName -eq 'File' -AND -Not$KeepTrace){Remove-Item $LFP -force -ea 0}
        # Output
        [PSCustomObject]@{
            Name = $TS
            Command  = $ScriptBlock
            Result = $Result
            Event = $Evt
            Start = $Start
            End = $End
            filter = [PSCustomObject]@{
                XPath = $XFilter
                MDE   = $MDEFilter
                Sentinel = $SentinelFilter
                }}}}
#############End




function Get-EzETW{
    [Alias('EzETW')]
    Param()
    [PsCustomObject]@{Command='Get-EzEvent';Alias='EzEvent';Help='Help EzEvent'}
    [PsCustomObject]@{Command='Get-EzEventFilter';Alias='EzFilter';Help='Help EzFilter'}
    [PsCustomObject]@{Command='Invoke-EzEventTracer';Alias='EzTracer';Help='Help EzEvent'}
    }
#End






Break
###########################################################################################


## Invoke-EzShark <-------------------------------------------------------------------- ? Shark ?
# EzShark [-Command] [-Snooze] [-Interface] [-Provider] [-KeepTrace] [-ToPCAP]
# EzShark -ListInterface [-Match] [-AsObject]
# EzShark -ListProvider [-Match] [-AsObject]





## ToDo

# Add Warning on errors function WarnError{}
# EzShark ?? ToPCAP
