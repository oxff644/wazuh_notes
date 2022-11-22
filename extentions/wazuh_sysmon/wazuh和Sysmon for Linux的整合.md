# 前言

从`4.3.X`开始，wazuh的规则集就包含了`sysmon`的规则，但是只是windows的。恰好最近在研究sysmon，便有了这篇文章。这篇文章主要介绍`wazuh和Sysmon for Linux的整合`。

# Sysmon for Linux

### 简介

`Sysmon` 是 `Windows Sysinternals 系列`中的一款工具。如果你想实时监控Windows系统又对其他第三方软件有顾虑，使用Sysmon这款**轻量级Microsoft自带内部软件**是最好的选择。

`应用打开或任何进程创建行为`发生时，Sysmon会使用 **sha1（默认），MD5，SHA256 或 IMPHASH**记录进程镜像文件的 **hash值**，包含进程创建过程中的进程 GUID，每个事件中包含`session 的 GUID`。除此之外记录磁盘和卷的**读取请求/网络连接（包括每个连接的源进程，IP 地址，端口号，主机名和端口名）**，重要的是还可在生成初期进程事件能记录在复杂的内核模式运行的**恶意软件。**

**项目地址：**[https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 原理

通过`系统服务和驱动程序`实现**记录进程创建、文件访问以及网络信息的记录**，并把相关的信息写入并展示在windows的日志事件里。**更多原理分析参考：**[https://www.anquanke.com/post/id/156704](https://www.anquanke.com/post/id/156704)

### 安装

与 Windows 的 Sysmon不同，**Linux用户需要自己编译程序**并确保他们拥有所有必需的依赖项，由于，**Sysmon依赖eBPF。所以要编译Sysmon，还必须首先安装EBPF。**（地址参考：[https://github.com/Sysinternals/SysinternalsE](https://github.com/Sysinternals/SysinternalsE)**BPF）**

#### eBPF是什么？

`eBPF(extended Berkeley Packet Filter)` 是一种可以在 Linux内核中运行用户编写的程序，而**不需要修改内核代码或加载内核模块的技术。**

简单说，eBPF 让 Linux 内核变得可编程化了。

eBPF 程序是一个事件驱动模型。Linux 内核提供了各种 hook point，比如 `system calls`, `function entry/exit`,`kernel tracepoints`, `network events`等。

**eBPF程序通过实现想要关注的hook point的callback，并把这些callback注册到相应的hook point来完成“内核编程”。**

#### eBPF的应用场景是什么？

* **网络优化**
eBPF兼具高性能和高可扩展特性，使得其成为网络方案中网络包处理的优选方案：

高性能 JIT编译器提供近乎内核本地代码的执行效率。

高可扩展 在内核的上下文里，可以快速地增加协议解析和路由策略

* **性能监控**
相比于传统的系统监控组件比如   sar，只能提供静态的counters和gauges，**eBPF支持可编程地动态收集和边缘计算聚合自定义的指标和事件**，极大地提升了性能监控的效率和想象空间。

* **安全控制**
**eBPF可以看到所有系统调用，所有网络数据包和socket网络操作**，一体化结合进程上下文跟踪，网络操作级别过滤，系统调用过滤，可以更好地提供安全控制。

* **故障诊断**
eBPF**通过kprobe，tracepoints跟踪机制兼具内核和用户的跟踪能力**，这种端到端的跟踪能力可以快速进行故障诊断，与此同时eBPF**支持以更加高效的方式透出profiling的统计数据**，而不需要像传统系统需要将大量的采样数据透出，使得持续地实时profiling成为可能。

在安装完成eBPF之后，就可以安装编译Sysmon了，这里按照[https://github.com/Sysinternals/SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux)一步步操作就行。

编译Sysmon后，可以通过键入`sudo ./sysmon -h`来查看帮助文件。

要使用该程序，首先**需要使用以下命令接受最终用户许可协议：**`sudo ./sysmon -accepteula`

这里你可以使用以下命令`指定一个配置文件或在没有配置文件`的情况下启动Sysmon。(建议还是制定一下，限制事件的生成范围，要不然日志文件的增长速度, you know..)

下面列出了 Sysmon for Linux 能够记录的当前事件 ID：

>1: Process Creation
>3: Network Connect
>5: Process Terminate
>9: RAW access read
>11: File Create / Overwrite
>16: Sysmon config change
>23: File Delete
```plain
sysmon -accepteula -i /path/to/config_file.xml 
```
**可以增加以下配置文件，用于记录所有支持的事件**：
```plain
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Event ID 1 == ProcessCreate. Log all newly created processes -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 3 == NetworkConnect Detected. Log all network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == ProcessTerminate. Log all processes terminated -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead. Log all raw access read -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess. Log all open process operations -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate. Log every file creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <!--Event ID 23 == FileDelete. Log all files being deleted -->
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
### 事件记录

启动后，Sysmon会将事件记录到`/var/log/syslog (Debian/Ubuntu based distros)`或者 `/var/log/messages” (Redhat/Fedora based distros)`中。

PS： 可通过Sysmon View辅助工具实现对其可视化显示。

在Debian/Ubuntu的日志格式如下：

```plain
Oct 20 21:21:45 test_ubuntu sysmon。<full_event_in_XML>。
```
其中 "test_ubuntu"是运行sysmon的机器的主机名。
在Redhat/Fedora中的日志格式:

```plain
Oct 20 21:22:30 test_fedora sysmon[sysmon_pid]: <full_event_in_XML>。
```
在这种情况下，sysmon进程的PID被加在方括号内。
添加以上配置文件后，ID:1 产生的系统事件：

```plain
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>1</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2022-10-20T21:21:50.643000000Z" />
      <EventRecordID>78947</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>test_ubuntu</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2022-10-22 21:21:50.650</Data>
      <Data Name="ProcessGuid">{277d2fec-8dfe-61cb-f1fe-8a16c6550000}</Data>
      <Data Name="ProcessId">37869</Data>
      <Data Name="Image">/usr/bin/tail</Data>
      <Data Name="FileVersion">-</Data>
      <Data Name="Description">-</Data>
      <Data Name="Product">-</Data>
      <Data Name="Company">-</Data>
      <Data Name="OriginalFileName">-</Data>
      <Data Name="CommandLine">tail -f /var/log/syslog</Data>
      <Data Name="CurrentDirectory">/home/0xff644</Data>
      <Data Name="User">root</Data>
      <Data Name="LogonGuid">{277d2fec-0000-0000-0000-000000000000}</Data>
      <Data Name="LogonId">0</Data>
      <Data Name="TerminalSessionId">79</Data>
      <Data Name="IntegrityLevel">no level</Data>
      <Data Name="Hashes">-</Data>
      <Data Name="ParentProcessGuid">{277d2fec-8df5-61cb-0587-c95ca5550000}</Data>
      <Data Name="ParentProcessId">37862</Data>
      <Data Name="ParentImage">/usr/bin/bash</Data>
      <Data Name="ParentCommandLine">bash</Data>
      <Data Name="ParentUser">root</Data>
   </EventData>
</Event>
```
ID：11 产生的系统事件,如下：
```plain
<?xml version="1.0" encoding="UTF-8"?>
<Event>
   <System>
      <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}" />
      <EventID>11</EventID>
      <Version>2</Version>
      <Level>4</Level>
      <Task>11</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2022-10-20T21:21:50.643000000Z" />
      <EventRecordID>78941</EventRecordID>
      <Correlation />
      <Execution ProcessID="21298" ThreadID="21298" />
      <Channel>Linux-Sysmon/Operational</Channel>
      <Computer>ubunutu2004vm</Computer>
      <Security UserId="0" />
   </System>
   <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2022-10-20 21:21:44.391</Data>
      <Data Name="ProcessGuid">{277d2fec-2501-61c8-8cd4-480000000000}</Data>
      <Data Name="ProcessId">6626</Data>
      <Data Name="Image">/var/ossec/bin/wazuh-agentd</Data>
      <Data Name="TargetFilename">/var/ossec/var/run/wazuh-agentd.state.temp</Data>
      <Data Name="CreationUtcTime">2022-10-20 21:21:44.391</Data>
      <Data Name="User">ossec</Data>
   </EventData>
</Event>
```
# wazuh和Sysmon for Linux整合

1）在agent端编译安装配置Sysmon; 2)采集agent日志； 3)编写wazuh规则解析日志生成告警事件。

**这里面最主要的挑战是在agent端将sysmon日志进行格式化，将它们从XML转换为JSON。**

为了实现这个目标，我写了一个python脚本，其逻辑如下：

**跟踪存储sysmon日志的文件（syslog/message）,在跟踪文件的同时，采用grep-alike管道，将非XML头与sysmon事件本身分开来。**

### 整合思路

1)首先进行常见的`xmltodict`解析，解析所有sysmon事件共有的XML部分，无论其ID如何（部分）；

2)**xmltodict解析取决于记录的sysmon事件ID**，在每种情况下提取部分的元数据；

3）解析后的事件被转换为`JSON`，并追加到**agent的active-responses.log中**；

4） 最后在Wazuh管理器（json解码器）添加自定义规则。

脚本如下：

```plain

### Script to Extract Sysmon for Linux Events
##########
# Tails /var/log/syslog
# Extracts the XML section of the sysmon log
# Applies XMLtoDICT to parse the event
# Converts to JSON and appends to the active responses log file
##########
import os
import time
import re
import xmltodict
import json
#Define the Regex Expression to match the log header:
#Oct 20 21:46:26 test_ubunutu sysmon:
regex = re.compile('^\w+\s[0-3][0-9]\s(?:[01]\d|2[0123]):(?:[012345]\d):(?:[012345]\d)\s\S+\ssysmon:\s')

def follow(thefile):
  thefile.seek(0, os.SEEK_END)
  while True:
      line = thefile.readline()
      if not line:
          time.sleep(0.1)
          continue
      yield line

def append_new_line(json_msg):
  with open('/var/ossec/logs/active-responses.log', "a+") as active_responses:
      active_responses.seek(0)
      data = active_responses.read(100)
      if len(data) > 0:
          active_responses.write("\n")

      active_responses.write(json.dumps(json_msg))
if __name__ == '__main__':
  logfile = open("/var/log/syslog","r")
  loglines = follow(logfile)
  for line in loglines:
      line_json = {}
      try:
          line_xml = regex.split(line)[1]
      except IndexError:
          continue
      else:
          line_xml = regex.split(line)[1]
          line_xml = xmltodict.parse(line_xml,disable_entities=True,process_namespaces=False)
          line_json["Event"] = {}
          line_json["Event"]["System"] = {}
          line_json["Event"]["EventData"] = {}
          line_json["Event"]["EventData"]["Data"] = {}
          line_json["Event"]["System"]["ProviderName"] = line_xml['Event']['System']['Provider']['@Name']
          line_json["Event"]["System"]["Guid"] = line_xml['Event']['System']['Provider']['@Guid']
          line_json["Event"]["System"]["EventID"] = line_xml['Event']['System']['EventID']
          line_json["Event"]["System"]["Version"] = line_xml['Event']['System']['Version']
          line_json["Event"]["System"]["Level"] = line_xml['Event']['System']['Level']
          line_json["Event"]["System"]["Task"] = line_xml['Event']['System']['Task']
          line_json["Event"]["System"]["Opcode"] = line_xml['Event']['System']['Opcode']
          line_json["Event"]["System"]["Keywords"] = line_xml['Event']['System']['Keywords']
          line_json["Event"]["System"]["Version"] = line_xml['Event']['System']['Version']
          line_json["Event"]["System"]["TimeCreated"] = line_xml['Event']['System']['TimeCreated']['@SystemTime']
          line_json["Event"]["System"]["EventRecordID"] = line_xml['Event']['System']['EventRecordID']
          line_json["Event"]["System"]["Correlation"] = line_xml['Event']['System']['Correlation']
          line_json["Event"]["System"]["ProcessID"] = line_xml['Event']['System']['Execution']['@ProcessID']
          line_json["Event"]["System"]["ThreadID"] = line_xml['Event']['System']['Execution']['@ThreadID']
          line_json["Event"]["System"]["Channel"] = line_xml['Event']['System']['Channel']
          line_json["Event"]["System"]["Computer"] = line_xml['Event']['System']['Computer']
          line_json["Event"]["System"]["UserId"] = line_xml['Event']['System']['Security']['@UserId']
          line_json["Event"]["EventData"]["Data"]["RuleName"] = line_xml['Event']['EventData']['Data'][0]['#text']
          line_json["Event"]["EventData"]["Data"]["UtcTime"] = line_xml['Event']['EventData']['Data'][1]['#text']
          line_json["Event"]["EventData"]["Data"]["ProcessGuid"] = line_xml['Event']['EventData']['Data'][2]['#text']
          if line_json["Event"]["System"]["EventID"] == '1':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["FileVersion"] = line_xml['Event']['EventData']['Data'][5]['#text']
              line_json["Event"]["EventData"]["Data"]["Description"] = line_xml['Event']['EventData']['Data'][6]['#text']
              line_json["Event"]["EventData"]["Data"]["Product"] = line_xml['Event']['EventData']['Data'][7]['#text']
              line_json["Event"]["EventData"]["Data"]["Company"] = line_xml['Event']['EventData']['Data'][8]['#text']
              line_json["Event"]["EventData"]["Data"]["OriginalFileName"] = line_xml['Event']['EventData']['Data'][9]['#text']
              line_json["Event"]["EventData"]["Data"]["CommandLine"] = line_xml['Event']['EventData']['Data'][10]['#text']
              line_json["Event"]["EventData"]["Data"]["CurrentDirectory"] = line_xml['Event']['EventData']['Data'][11]['#text']
              line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][12]['#text']
              line_json["Event"]["EventData"]["Data"]["LogonGuid"] = line_xml['Event']['EventData']['Data'][13]['#text']
              line_json["Event"]["EventData"]["Data"]["LogonId"] = line_xml['Event']['EventData']['Data'][14]['#text']
              line_json["Event"]["EventData"]["Data"]["TerminalSessionId"] = line_xml['Event']['EventData']['Data'][15]['#text']
              line_json["Event"]["EventData"]["Data"]["IntegrityLevel"] = line_xml['Event']['EventData']['Data'][16]['#text']
              line_json["Event"]["EventData"]["Data"]["Hashes"] = line_xml['Event']['EventData']['Data'][17]['#text']
              line_json["Event"]["EventData"]["Data"]["ParentProcessGuid"] = line_xml['Event']['EventData']['Data'][18]['#text']
              line_json["Event"]["EventData"]["Data"]["ParentProcessId"] = line_xml['Event']['EventData']['Data'][19]['#text']
              line_json["Event"]["EventData"]["Data"]["ParentImage"] = line_xml['Event']['EventData']['Data'][20]['#text']
              line_json["Event"]["EventData"]["Data"]["ParentCommandLine"] = line_xml['Event']['EventData']['Data'][21]['#text']
              line_json["Event"]["EventData"]["Data"]["ParentUser"] = line_xml['Event']['EventData']['Data'][22]['#text']
          elif line_json["Event"]["System"]["EventID"] == '3':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][5]['#text']
              line_json["Event"]["EventData"]["Data"]["Protocol"] = line_xml['Event']['EventData']['Data'][6]['#text']
              line_json["Event"]["EventData"]["Data"]["Initiated"] = line_xml['Event']['EventData']['Data'][7]['#text']
              line_json["Event"]["EventData"]["Data"]["SourceIsIpv6"] = line_xml['Event']['EventData']['Data'][8]['#text']
              line_json["Event"]["EventData"]["Data"]["SourceIp"] = line_xml['Event']['EventData']['Data'][9]['#text']
              line_json["Event"]["EventData"]["Data"]["SourceHostname"] = line_xml['Event']['EventData']['Data'][10]['#text']
              line_json["Event"]["EventData"]["Data"]["SourcePort"] = line_xml['Event']['EventData']['Data'][11]['#text']
              line_json["Event"]["EventData"]["Data"]["SourcePortName"] = line_xml['Event']['EventData']['Data'][12]['#text']
              line_json["Event"]["EventData"]["Data"]["DestinationIsIpv6"] = line_xml['Event']['EventData']['Data'][13]['#text']
              line_json["Event"]["EventData"]["Data"]["DestinationIp"] = line_xml['Event']['EventData']['Data'][14]['#text']
              line_json["Event"]["EventData"]["Data"]["DestinationHostname"] = line_xml['Event']['EventData']['Data'][15]['#text']
              line_json["Event"]["EventData"]["Data"]["DestinationPort"] = line_xml['Event']['EventData']['Data'][16]['#text']
              line_json["Event"]["EventData"]["Data"]["DestinationPortName"] = line_xml['Event']['EventData']['Data'][17]['#text']
          elif line_json["Event"]["System"]["EventID"] == '5':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][5]['#text']
          elif line_json["Event"]["System"]["EventID"] == '9':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["Device"] = line_xml['Event']['EventData']['Data'][5]['#text']
          elif line_json["Event"]["System"]["EventID"] == '11':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["TargetFilename"] = line_xml['Event']['EventData']['Data'][5]['#text']
              line_json["Event"]["EventData"]["Data"]["CreationUtcTime"] = line_xml['Event']['EventData']['Data'][6]['#text']
              line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][7]['#text']
          elif line_json["Event"]["System"]["EventID"] == '16':
              line_json["Event"]["EventData"]["Data"]["Configuration"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["ConfigurationFileHash"] = line_xml['Event']['EventData']['Data'][4]['#text']
          elif line_json["Event"]["System"]["EventID"] == '23':
              line_json["Event"]["EventData"]["Data"]["ProcessID"] = line_xml['Event']['EventData']['Data'][3]['#text']
              line_json["Event"]["EventData"]["Data"]["User"] = line_xml['Event']['EventData']['Data'][4]['#text']
              line_json["Event"]["EventData"]["Data"]["Image"] = line_xml['Event']['EventData']['Data'][5]['#text']
              line_json["Event"]["EventData"]["Data"]["TargetFilename"] = line_xml['Event']['EventData']['Data'][6]['#text']
              line_json["Event"]["EventData"]["Data"]["Hashes"] = line_xml['Event']['EventData']['Data'][7]['#text']
              line_json["Event"]["EventData"]["Data"]["IsExecutable"] = line_xml['Event']['EventData']['Data'][8]['#text']
              line_json["Event"]["EventData"]["Data"]["Archived"] = line_xml['Event']['EventData']['Data'][9]['#text']
          append_new_line(line_json)
```
脚本通过`active-response`触发，当agent启动之后,依赖规则`rule_id=501|502|503`，**通过在agent上定时执行bash脚本，对运行的python脚本进行权限检查，并执行**。
脚本放在/var/ossec/active-response/bin/目录下

```plain
#!/bin/bash
if pgrep -u root,ossec -f sysmon_for_linux.py
then
  exit 1;
else
  /usr/bin/python3 /var/ossec/active-response/bin/sysmon_for_linux.py
fi
```
然后在wazuh manager的`agent.conf`中配置：
```plain
<command>
  <name>sysmon-for-linux</name>
  <executable>sysmon_for_linux.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
 <disabled>no</disabled>
  <command>sysmon-for-linux</command>
  <location>local</location>
  <rules_id>501,502,503</rules_id>
</active-response>

```
然后在`wazuh manager`中新增如下规则：
```plain
<!--
- Sysmon For Linux rules
- Created by 0xff644.
- https://github.com/oxff644
-->

<group name="linux,sysmon, ">
  <rule id="200150" level="3">
      <decoded_as>json</decoded_as>
      <field name="Event.System.ProviderName">^Linux-Sysmon$</field>
      <description>Sysmon For Linux</description>
      <options>no_full_log</options>
  </rule>
  <rule id="200151" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^1$</field>
      <group>sysmon_event1</group>
      <description>Sysmon - Event 1: Process creation $(Event.EventData.Data.Image)</description>
      <mitre>
       <id>T1204</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200152" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^3$</field>
      <description>Sysmon - Event 3: Network connection by $(Event.EventData.Data.Image)</description>
      <group>sysmon_event3</group>
      <mitre>
       <id>T1043</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200153" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^5$</field>
      <description>Sysmon - Event 5: Process terminated $(Event.EventData.Data.Image)</description>
      <group>sysmon_event5</group>
      <mitre>
       <id>T1204</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200154" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^9$</field>
      <description>Sysmon - Event 9: Raw Access Read by $(Event.EventData.Data.Image)</description>
      <group>sysmon_event9</group>
      <mitre>
       <id>T1204</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200155" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^11$</field>
      <description>Sysmon - Event 11: FileCreate by $(Event.EventData.Data.Image)</description>
  <group>sysmon_event_11</group>
      <mitre>
       <id>T1044</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200156" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^16$</field>
      <description>Sysmon - Event 16: Sysmon config state changed $(Event.EventData.Data.Configuration)</description>
      <group>sysmon_event_16</group>
      <mitre>
       <id>T1562</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
  <rule id="200157" level="3">
      <if_sid>200150</if_sid>
      <field name="Event.System.EventID">^23$</field>
      <description>Sysmon - Event 23: FileDelete (A file delete was detected) by $(Event.EventData.Data.Image)</description>
      <group>sysmon_event_23</group>
      <mitre>
       <id>T1107</id>
       <id>T1485</id>
      </mitre>
      <options>no_full_log</options>
  </rule>
</group>
```
PS：规则中的MITRE ID是比较通用的，主要用于对Sysmon生成的事件类型增加更多粒度的展示。
#### 告警展示

```plain
{
 "timestamp":"2022-10-20T22:59:50.382+0000",
 "rule":{
    "level":3,
    "description":"Sysmon - Event 11: FileCreate by /var/ossec/bin/wazuh-agentd",
    "id":"200155",
    "mitre":{
       "id":[
          "T1044"
       ],
       "tactic":[
          "Persistence",
          "Privilege Escalation"
       ],
       "technique":[
          "File System Permissions Weakness"
       ]
    },
    "firedtimes":7983,
    "mail":false,
    "groups":[
       "linux",
       "sysmon",
       "sysmon_event_11"
    ]
 },
 "agent":{
    "id":"017",
    "name":"test_ubunutu",
    "ip":"192.168.252.191",
    "labels":{
       "customer":"3c59"
    }
 },
 "manager":{
    "name":"wazuh-01"
 },
 "id":"1640756096.99481500",
 "decoder":{
    "name":"json"
 },
 "data":{
    "Event":{
       "System":{
          "ProviderName":"Linux-Sysmon",
          "Guid":"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}",
          "EventID":"11",
          "Version":"2",
          "Level":"4",
          "Task":"11",
          "Opcode":"0",
          "Keywords":"0x8000000000000000",
          "TimeCreated":"2022-10-20T22:59:50.738308000Z",
          "EventRecordID":"166705",
          "Correlation":"null",
          "ProcessID":"21298",
          "ThreadID":"21298",
          "Channel":"Linux-Sysmon/Operational",
          "Computer":"test_ubunutu",
          "UserId":"0"
       },
       "EventData":{
          "Data":{
             "RuleName":"-",
             "UtcTime":"2022-10-20 22:59:50.746",
             "ProcessGuid":"{277d2fec-2501-61c8-8cd4-480000000000}",
             "ProcessID":"6626",
             "Image":"/var/ossec/bin/wazuh-agentd",
             "TargetFilename":"/var/ossec/var/run/wazuh-agentd.state.temp",
             "CreationUtcTime":"2022-10-20 22:59:50.746",
             "User":"ossec"
          }
       }
    }
 },
 "location":"/var/ossec/logs/active-responses.log"
}
```
# Reference

* [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [https://github.com/Sysinternals/SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux)
* [https://github.com/Sysinternals/SysinternalsEBPF](https://github.com/Sysinternals/SysinternalsEBPF)
* [https://blog.csdn.net/sinat_22338935/article/details/123002910](https://blog.csdn.net/sinat_22338935/article/details/123002910)
* [https://www.anquanke.com/post/id/156704](https://www.anquanke.com/post/id/156704)
* [https://cloud.tencent.com/developer/article/1041591](https://cloud.tencent.com/developer/article/1041591)
* [https://www.anquanke.com/post/id/156704](https://www.anquanke.com/post/id/156704)
* [https://www.anquanke.com/post/id/180418](https://www.anquanke.com/post/id/180418)
* [https://superuser.com/questions/1482486/installation-error-of-sysmon-on-windows-7-vm-sysmondrv-driver-and-startservice](https://superuser.com/questions/1482486/installation-error-of-sysmon-on-windows-7-vm-sysmondrv-driver-and-startservice)
* [https://www.yuque.com/p1ut0/xer98r/ugrtrf](https://www.yuque.com/p1ut0/xer98r/ugrtrf)
* 

 

