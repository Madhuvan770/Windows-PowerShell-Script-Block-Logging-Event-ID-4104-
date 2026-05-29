title: Threat Hunting - Suspicious Code Patterns In PowerShell Script Blocks
id: c4e3b1a8-8fbc-410a-b5f7-f1093207635e
status: experimental
description: Detects custom threat hunting, dual-use, or offensive scripts executing unique code patterns like manual socket parsing, memory querying, or anti-forensics directly inside a script block.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
author: Senior Security Analyst / Detection Engineer
date: 2026-05-29
tags:
    - attack.execution
    - attack.t1059.001
    - attack.discovery
    - attack.t1046
logsource:
    product: windows
    category: ps_script
    definition: 'Requires Windows PowerShell Script Block Logging enabled (Event ID 4104)'
detection:
    # 1. Custom discovery via raw network socket operations (Bypassing native Cmdlets like Test-NetConnection)
    selection_network_hunt:
        ScriptBlockText|contains|all:
            - 'System.Net.Sockets.TcpClient'
            - '.Connect('
            - 'BeginConnect'
            
    # 2. Defensive evasion / AMSI & ETW bypass logic natively found in custom execution scripts
    selection_evasion:
        ScriptBlockText|contains:
            - 'AmsiScanBuffer'
            - 'amsiInitFailed'
            - 'EtwEventWrite'
            
    # 3. Memory dump / Process injection mechanisms often embedded in advanced tooling
    selection_memory_hunt:
        ScriptBlockText|contains|all:
            - 'VirtualAlloc'
            - 'CreateThread'
            - 'Marshal.Copy'

    # 4. Low-level configuration discovery using raw WMI objects rather than built-in cmdlets
    selection_wmi_hunt:
        ScriptBlockText|contains|all:
            - 'Management.ManagementObjectSearcher'
            - 'Select * from'

    # Exclude known, trusted deployment scripts or administrative frameworks (Tune this section)
    filter_admin_tools:
        ScriptBlockText|contains:
            - 'C:\Program Files\Microsoft Monitoring Agent\'
            - 'HealthService.exe'
            - 'Invoke-PolicyEvaluation'

    condition: (1 of selection_*) and not filter_admin_tools
falsepositives:
    - Highly customized internal network monitoring or asset discovery scripts built by internal DevOps/SysAdmin teams.
    - Legacy health-check scripts for complex enterprise applications.
level: high
