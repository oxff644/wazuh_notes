**USING WAZUH AND CHAINSAW FOR WINDOWS EVT LOGS FORENSIC ANALYSIS**


## 前言


本篇文章主要介绍Wazuh和[Chainsaw](https://github.com/countercept/chainsaw)集成做取证分析。

Chainsaw是由[F-Secure]（https://www.f-secure.com/en） 开发的免费工具。 Chainsaw提供了一个强大的快速响应能力，能快速识别Windows事件日志中的威胁。它提供了一种通用和快速的方法来搜索事件日志中的关键词，并通过使用内置的检测逻辑和对Sigma检测规则的支持来识别威胁。




## Chainsaw

```
---
name: Chainsaw's Sigma mappings for Event Logs
kind: evtx
rules: sigma

ignore:
  - Defense evasion via process reimaging
  - Exports Registry Key To an Alternate Data Stream
  - NetNTLM Downgrade Attack
  - Non Interactive PowerShell
  - Wuauclt Network Connection

groups:
  - name: Suspicious Process Creation
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 1
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Command Line
        from: CommandLine
        to: Event.EventData.CommandLine
      - name: Original File Name
        from: OriginalFileName
        to: Event.EventData.OriginalFileName
      - name: Parent Image
        from: ParentImage
        to: Event.EventData.ParentImage
      - name: Parent Command Line
        from: ParentCommandLine
        to: Event.EventData.ParentCommandLine

  - name: Suspicious Network Connection
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 3
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: User
        to: Event.EventData.User
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Destination IP
        from: DestinationIp
        to: Event.EventData.DestinationIp
      - name: Destination Port
        from: DestinationPort
        to: Event.EventData.DestinationPort
      - name: Destination Hostname
        from: DestinationHostname
        to: Event.EventData.DestinationHostname
      - name: Destination Is IPv6
        from: DestinationIsIpv6
        to: Event.EventData.DestinationIsIpv6
        visible: false
      - name: Initiated
        from: Initiated
        to: Event.EventData.Initiated
      - name: Source Port
        from: SourcePort
        to: Event.EventData.SourcePort

  - name: Suspicious Image Load
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 7
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Image Loaded
        from: ImageLoaded
        to: Event.EventData.ImageLoaded

  - name: Suspicious File Creation
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 11
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Target File Name
        from: TargetFilename
        to: Event.EventData.TargetFilename

  - name: Suspicious Registry Event
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 13
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Details
        from: Details
        to: Event.EventData.Details
      - name: Target Object
        from: TargetObject
        to: Event.EventData.TargetObject

  - name: Suspicious Service Installed
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 7045
      Provider: Service Control Manager
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Service
        from: ServiceName
        to: Event.EventData.ServiceName
      # TODO: Can someone check if this is a typo...?
      - name: Command Line
        from: CommandLine
        to: Event.EventData.ImagePath

  - name: Suspicious Command Line
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 4688
      Provider: Microsoft-Windows-Security-Auditing
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: UserName
        to: Event.EventData.SubjectUserName
      # TODO: Can someone check if this is a typo...?
      - name: Process
        from: Image
        to: Event.EventData.NewProcessName
      - name: Command Line
        from: CommandLine
        to: Event.EventData.CommandLine

  - name: Suspicious Scheduled Task Created
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 4698
      Provider: Microsoft-Windows-Security-Auditing
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: UserName
        to: Event.EventData.SubjectUserName
      - name: Name
        from: TaskName 
        to: Event.EventData.TaskName
      # TODO: Can someone check if this is a typo...?
      - name: Command Line
        from: CommandLine
        to: Event.EventData.TaskContent

```


## Workflow



1. 无论采用何种执行方式（在一台机器或几台机器上的本地执行，通过wodle命令在所有windows机器上触发，等等），powerhell脚本（见下文）将执行chainsaw，将输出到CSV文件，将这些CSV转换为JSON，输出到active-response.log中；
2. 在循环过程中，流量控制（睡眠定时器）将防止填满代理的队列；
3. Wazuh管理器中的检测规则将产生相应的警报。

注意：在Chainsaw的CSV文件生成中存在一个[问题](https://github.com/countercept/chainsaw/issues/35)，带有"\r "的列会导致该行/列的中断，并被分割成两个不同行。

文件夹 "c:\Program Files "用于存储带有可执行文件和所有西格玛规则的Chainsaw文件夹。这里根据你的需求，在powerhell脚本中改变文件夹的位置和设置。


执行方式：


```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\socfortress\chainsaw\chainsaw.ps1"
```

Chainsaw也可以定期执行，由Wazuh管理器上的wodle命令配置触发。

基于前面提到的Chainsaw类别，我们现在可以建立Wazuh的检测规则。
