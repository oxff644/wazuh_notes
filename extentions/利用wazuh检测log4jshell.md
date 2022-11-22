# 前言

`Apache Log4j2`是一款优秀的开源日志框架，被全世界企业和组织广泛应用于各种业务系统开发。最近，Apache中log4j2 RCE漏洞爆发之后，危害严重，影响范围极大。

受影响的Apache Log4j 2版本是`2.0-beta9到2.16`，最初修复该漏洞的`2.15.0`版本后来被发现仍然存在漏洞。

因此，官方建议更新到`2.16.0`版本，该版本`禁用JNDI并完全删除%m{lookups}`，但2.16版本后来也被爆出漏洞-。-

本篇文章不涉及漏洞分析复现，仅讲述`如何``利用Wazuh``检测log4j shell`，废话不多说，咱们开始吧。

# 思路及实现

## 实现思路

#### 思路一：使用wazuh的SCA（Security Configuration Assessment）策略

>SCA策略是以YAML格式编写的，通常用来对系统加固情况的检查（基线检测），在大部分情况下，可以用来检测漏洞组件。参考：[https://](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[documentat](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[i](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[on](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[.](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[wazuh.c](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[o](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[m/cu](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[rre](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[n](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[t/](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[user](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[-ma](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[nual](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[/](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[c](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[apa](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[biliti](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[e](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[s/sec-co](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[n](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[fig-](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[a](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[ssessm](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[ent](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[/cre](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[a](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[ting-](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[c](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[us](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[t](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[om-pol](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[i](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)[cies.html?highlight=sca](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html?highlight=sca)
#### 实现过程

**Se****ver****端**

**s****te****p****1** :  在`/var/``o``s``se``c/``e``tc/``s``hared/default/`目录下新建一个新的检测策略log4j_check.yml，策略内容如下：

```plain
policy:
  id: "log4j_check"
  file: "log4j_check.yml"
  name: "Log4j dependency check"
  description: "This document provides prescriptive guidance for identifying Log4j RCE vulnerability"
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance
requirements:
  title: "Check if Java is present on the machine"
  description: "Requirements for running the SCA scan against machines with Java on them."
  condition: all
  rules:
    - 'c:sh -c "ps aux | grep java | grep -v grep" -> r:java'
checks:
  - id: 10000
    title: "Ensure Log4j is not on the system or under 2.17"
    description: "The Log4j library is vulnerable to RCE on versions between 2.10 and 2.16."
    remediation: "Update the log4j library to version 2.16 or set log4j2.formatMsgNoLookups to true if possible."
    condition: none
    rules:
      - 'c:find / -regex ".*log4j.*.jar" -type f -exec sh -c "unzip -p {} META-INF/MANIFEST.MF | grep Implementation-Version" \; -> r: 2.10.| 2.11.| 2.12.| 2.13.| 2.14.| 2.15.|2.16.'
  - id: 10001
    title: "Ensure Java is not running or is properly configured"
    description: "The Log4j library is vulnerable to RCE on versions between 2.10 and 2.16."
    remediation: "Update the log4j library to version 2.17 or set log4j2.formatMsgNoLookups to true if possible."
    condition: any
    rules:
      - 'c:sh -c "ps aux | grep java | grep -v grep" -> r:java && r:Dlog4j2.formatMsgNoLookups=true'
```
>这里需要注意的是，`default`是默认组，在没有修改的情况下，里面包括了`所有`agent。我们新建的这条这策略是共享策略，会作用与这个默认组（default）下的所有agent，同时你可能也注意到了我使用的查找命令是`f``in``d`，所以为了不影响业务，建议在进行测试时，新建一个测试组，将几个不同配置的agent划进去，测试一下性能问题。
**step2** : 权限修改

```plain
chown ossec:ossec /var/ossec/etc/shared/default/log4j_check.yml
```
**step3** : 为了让这个策略启用，我们需要在`/var/``os``sec/e``t``c/``s``hared/default/agent.conf`中添加如下配置：
```plain
<agent_config>
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>24h</interval>
    <skip_nfs>yes</skip_nfs>    
    <policies> 
      <policy>/var/ossec/etc/shared/log4j_check.yml</policy>  
    </policies>
  </sca>
</agent_config>
```
**agent端**
**step1** : 添加agent配置

为了让agent能接收server端的SCA策略并执行命令，我们需要配置：

```plain
echo "sca.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
```
>当然你可以将SCA策略手动同步到agent上面的话，就不用这样配置啦。**step2** : 重启agent
```plain
systemctl restart wazuh-agent
```
#### 简单扩展: **监测web日志**

**Server端**

**step1**: 在`/var/ossec/etc/rules/local_rules.xml`中添加如下规则

```plain
<group name="log4j, attack,">
  <rule id="110002" level="7">
    <if_group>web|accesslog|attack</if_group>
    <regex type="pcre2">(?i)(((\$|24)\S*)((\{|7B)\S*)((\S*j\S*n\S*d\S*i))|JHtqbmRp)</regex>
    <description>Possible Log4j RCE attack attempt detected.</description>
    <mitre>
      <id>T1190</id>
      <id>T1210</id>
      <id>T1211</id>
    </mitre>
  </rule>

  <rule id="110003" level="12">
    <if_sid>110002</if_sid>
    <regex type="pcre2">ldap[s]?|rmi|dns|nis|iiop|corba|nds|http|lower|upper|(\$\{\S*\w\}\S*)+</regex>
    <description>Log4j RCE attack attempt detected.</description>
    <mitre>
      <id>T1190</id>
      <id>T1210</id>
      <id>T1211</id>
    </mitre>
  </rule>
</group>
```
**step2** : 重启wazuh manager让规则生效
```plain
systemctl restart wazuh-manager
```
#### agent端

在某些情况下，Wazuh可能还没有监控web日志。可以通过修改Wazuh服务器侧的配置组来启用日志数据收集。此处，我们以apache日志为例，在/var/ossec/etc/shared/default/agent.conf中添加localfile模块来启用日志收集，配置如下：

```plain
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```
为了测试效果，可以尝试构造一下恶意请求，例如
```plain
http://localhost/?x=${jndi:ldap://${localhost}.{{test}}/a}
```
## 思路二（推荐）

### Wodle Command

在Wazuh中Wodle模块可以用来配置对机器进行安全扫描。但是前提条件是要在agent上启用接收远程命令执行。参考（[htt](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[p](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[s://d](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[o](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[cumentation.wazuh.com/cur](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[r](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[en](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[t](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[/user-manua](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[l](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[/reference/daemons/wazuh-modulesd.html?h](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[i](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[ghligh](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[t](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[=wodle%20comma](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[n](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)[d](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html?highlight=wodle%20command)）

### 实现思路

* 通过wodle command运行bash脚本，在运行的进程中查找.jar的扩展名，包括Docker镜像。
* 收集进程ID、log4j版本、JNDI启用条件和进程命令行。
* 将输出格式转化为json格式，并将结果添加到agent的active-responses.log文件中。
### 实现过程

**step1**: 在agent端启用接收远程命令执行。

```plain
echo "wazuh_command.remote_commands=1"" >> /var/ossec/etc/local_internal_options.conf
```
**step2** : 在`server`端的`/var/ossec/etc/shared/default/agent.conf` 添加如下配置：
```plain
<wodle name="command">
  <disabled>no</disabled>
  <tag>log4j-scan</tag>
  <command>/usr/bin/bash /var/ossec/wodles/command/log4j_scan.sh</command>
  <interval>24h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
log4j_scan.sh的内容如下：
```plain
###########################
##查找.jar的扩展名，包括Docker镜像
###收集进程ID、log4j版本、JNDI启用条件和进程命令行
####将输出格式转化为json格式，并将结果添加到agent的active-responses.log文件中
#############################
#!/bin/bash
LOCAL=`dirname $0`

LOG_FILE="/var/ossec/logs/active-responses.log"
scan_output() {
        now=$(date)
        pid=$1
        log4j_version=$2
        has_jndilookupclass=$3
        jar_path=$4
        process_cmd_line=$(tr "\000" " " < /proc/${pid}/cmdline)
        container_id=$(grep -Po -m 1 "((.*/docker/\K.*)|(.*/k8s.io/\K.*))" /proc/${pid}/cgroup)
        if [[ -n ${container_id} ]]; then
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'", "container_id":"'"$container_id"'", "process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        fi
        if [[ -n ${container_id} ]]; then
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'", "container_id":"'"$container_id"'", "process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        else
                 scan_output='{"scan_date":"'"$now"'", "process_id":"'"$pid"'", "log4j_version":"'"$log4j_version"'", "has_jndilookupclass":"'"$has_jndilookupclass"'", "jar_path":"'"$jar_path"'","process_cmd_line":"'"$process_cmd_line"'"}'
                 while read -r line; do
                   echo $line >> ${LOG_FILE}
                   sleep 0.1
                 done <<< "$scan_output"
        fi    
}

main() {
        # 检查所有正在运行的带有加载的jar文件的进程
        find /proc/*/fd/ -type l 2>/dev/null | while read line; do
                # print a spinner
                sp="/-\|"
                printf "\b${sp:i++%${#sp}:1}"

                # resolve the file descriptor target
                link_target=$(readlink ${line})

                # skip non jar files
                if [[ "$link_target" != *.jar ]]; then
                        continue
                fi

                # 通过procfs检查容器化进程
                proc_base=${line%/*/*}
                pid=${proc_base##*/}
                abs_path=$proc_base/root$link_target





                if [[ "$abs_path" =~ log4j-core.*jar ]]; then
                        # log4j-core is loaded
                        found_log4j=true
                        log4j_jar_name=${abs_path%.*}
                        log4j_version=${log4j_jar_name##*-*-}
                else
                        log4j_match=$(grep -aio -m 1 "log4j-core.*jar" ${abs_path})
                        # skip files without log4j
                        if [[ -z "$log4j_match" ]]; then
                                continue
                        else
                                found_log4j=true
                                log4j_jar_name=${log4j_match%.*}
                                log4j_version=${log4j_jar_name##*-*-}
                        fi
                fi

                # 跳过已经检查过的路径
                if [[ ${matched_files[@]} =~ $abs_path ]]; then
                        continue
                else
                        matched_files+=($abs_path)
                fi

               #在jar中查找JndiLooup漏洞类

                if grep -q -l -r -m 1 JndiLookup.class $abs_path; then
                        has_jndilookupclass=true
                else
                        has_jndilookupclass=false
                fi

                scan_output $pid $log4j_version $has_jndilookupclass $link_target
        done
}
main
```
**step3** : 在`/v``a``r/ossec/``e``tc/``r``ules/local_rules.xml`添加以下规则：
```plain
<group name="vulnerability-detector,log4j,">
    <rule id="96605" level="13">
        <decoded_as>json</decoded_as>
        <field name="scan_date">\.+</field>
        <field name="process_id">\.+</field>
        <field name="log4j_version">\.+</field>
        <description>log4j Alert - Vulnerable Packages - JNDI Lookup Class:  $(has_jndilookupclass)</description>
        <options>no_full_log</options>
    </rule>
</group>
```
### 实现效果

```plain
Rule: 96605 fired (level 13) -> "log4j Alert - Vulnerable Packages - JNDI Lookup Class:  true"
Portion of the log(s):
{
   "scan_date":"Thu 23 Dec 2021 08:31:12 PM UTC",
   "process_id":"77077",
   "log4j_version":"2.11.1",
   "has_jndilookupclass":"true",
   "jar_path":"/usr/share/elasticsearch/lib/log4j-core-2.11.1.jar",
   "process_cmd_line":"/usr/share/elasticsearch/jdk/bin/java -Xshare:auto -Des.networkaddress.cache.ttl=60 -Des.networkaddress.cache.negative.ttl=10 -XX:+AlwaysPreTouch -Xss1m -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djna.nosys=true -XX:-OmitStackTraceInFastThrow -XX:+ShowCodeDetailsInExceptionMessages -Dio.netty.noUnsafe=true -Dio.netty.noKeySetOptimization=true -Dio.netty.recycler.maxCapacityPerThread=0 -Dio.netty.allocator.numDirectArenas=0 -Dlog4j.shutdownHookEnabled=false -Dlog4j2.disable.jmx=true -Djava.locale.providers=SPI,COMPAT -Xms1g -Xmx1g -XX:+UseG1GC -XX:G1ReservePercent=25 -XX:InitiatingHeapOccupancyPercent=30 -Djava.io.tmpdir=/tmp/elasticsearch-17442157478472768084 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/lib/elasticsearch -XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log -Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m -XX:MaxDirectMemorySize=536870912 -Des.path.home=/usr/share/elasticsearch -Des.path.conf=/etc/elasticsearch -Des.distribution.flavor=oss -Des.distribution.type=deb -Des.bundled_jdk=true -cp /usr/share/elasticsearch/lib/elasticsearch-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-cli-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-core-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-geo-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-launchers-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-plugin-classloader-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-secure-sm-7.10.2.jar /usr/share/elasticsearch/lib/elasticsearch-x-content-7.10.2.jar /usr/share/elasticsearch/lib/HdrHistogram-2.1.9.jar /usr/share/elasticsearch/lib/hppc-0.8.1.jar /usr/share/elasticsearch/lib/jackson-core-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-cbor-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-smile-2.10.4.jar /usr/share/elasticsearch/lib/jackson-dataformat-yaml-2.10.4.jar /usr/share/elasticsearch/lib/java-version-checker-7.10.2.jar /usr/share/elasticsearch/lib/jna-5.5.0.jar /usr/share/elasticsearch/lib/joda-time-2.10.4.jar /usr/share/elasticsearch/lib/jopt-simple-5.0.2.jar /usr/share/elasticsearch/lib/jts-core-1.15.0.jar /usr/share/elasticsearch/lib/log4j-api-2.11.1.jar /usr/share/elasticsearch/lib/log4j-core-2.11.1.jar /usr/share/elasticsearch/lib/lucene-analyzers-common-8.7.0.jar /usr/share/elasticsearch/lib/lucene-backward-codecs-8.7.0.jar /usr/share/elasticsearch/lib/lucene-core-8.7.0.jar /usr/share/elasticsearch/lib/lucene-grouping-8.7.0.jar /usr/share/elasticsearch/lib/lucene-highlighter-8.7.0.jar /usr/share/elasticsearch/lib/lucene-join-8.7.0.jar /usr/share/elasticsearch/lib/lucene-memory-8.7.0.jar /usr/share/elasticsearch/lib/lucene-misc-8.7.0.jar /usr/share/elasticsearch/lib/lucene-queries-8.7.0.jar /usr/share/elasticsearch/lib/lucene-queryparser-8.7.0.jar /usr/share/elasticsearch/lib/lucene-sandbox-8.7.0.jar /usr/share/elasticsearch/lib/lucene-spatial3d-8.7.0.jar /usr/share/elasticsearch/lib/lucene-spatial-extras-8.7.0.jar /usr/share/elasticsearch/lib/lucene-suggest-8.7.0.jar /usr/share/elasticsearch/lib/snakeyaml-1.26.jar /usr/share/elasticsearch/lib/spatial4j-0.7.jar /usr/share/elasticsearch/lib/t-digest-3.2.jar /usr/share/elasticsearch/lib/tools org.elasticsearch.bootstrap.Elasticsearch -p /var/run/elasticsearch/elasticsearch.pid --quiet "
}
```
# Reference

[https://documentation.wazuh.com/current/index.html](https://documentation.wazuh.com/current/index.html)

 

