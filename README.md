# mos-chinadns

* 支持DoH，IPv6，EDNS Client Subnet(ECS)，根据域名和IP的分流。
* 可一步实现传统分流方案 `ChinaDNS(IP分流) + dnscrypt(DoH) + dnsmasq-china-list + dnsmasq(域名分流)`的效果。
* 有更高的性能。
  * [DoH性能可能是dnscrypt的10倍](https://github.com/valyala/fasthttp#http-client-comparison-with-nethttp)
  * [域名分流性能可能是dnsmasq的千倍](#和dnsmasq一起使用)
  * 可显著降低路由类设备的负载与延时
* release已附带大陆IP和域名表，开箱即用。

---

- [mos-chinadns](#mos-chinadns)
  - [三分钟快速上手](#三分钟快速上手)
  - [命令帮助](#命令帮助)
  - [更新大陆ip与域名表](#更新大陆ip与域名表)
  - [分流效果](#分流效果)
  - [和dnsmasq一起使用](#和dnsmasq一起使用)
  - [其他细节](#其他细节)
  - [配置文件](#配置文件)
  - [Open Source Components / Libraries / Reference](#open-source-components--libraries--reference)

## 三分钟快速上手

在这里下载最新版本：[release](https://github.com/IrineSistiana/mos-chinadns/releases)

大陆IP表`chn.list`和域名表`chn_domain.list`已包含在release的zip包中。

从以下预设配置选择一个适合自己的(如果不清楚，用预设配置1)，复制并保存至`config.json`，确保`chn.list`，`chn_domain.list`，`config.json`和`mos-chinadns`在同一目录。

<details><summary><code>预设配置1 分流 使用DoH</code></summary><br>

国内域名使用阿里云DNS，国际域名使用Cloudflare DoH。

    {
        "bind_addr": "127.0.0.1:53",
        "local_server": "223.5.5.5:53",
        "remote_server": "1.1.1.1:443",
        "remote_server_url": "https://1.1.1.1/dns-query",
        "local_allowed_ip_list": "./chn.list",
        "local_forced_domain_list": "./chn_domain.list"
    }

</details>

<details><summary><code>预设配置2 分流</code></summary><br>

国内域名使用阿里云DNS，国际域名使用OpenDNS。

    {
        "bind_addr": "127.0.0.1:53",
        "local_server": "223.5.5.5:53",
        "remote_server": "208.67.222.222:443",
        "local_allowed_ip_list": "./chn.list",
        "local_forced_domain_list": "./chn_domain.list"
    }

</details>

<details><summary><code>预设配置3 DoH客户端</code></summary><br>

无分流。将mos-chinadns作为简单的DoH客户端。

    {
        "bind_addr": "127.0.0.1:53",
        "remote_server": "8.8.8.8:443",
        "remote_server_url": "https://dns.google/dns-query",
    }

</details>

用以下命令启动

    mos-chinadns -c config.json -dir2exe

## 命令帮助

    -c string   [路径]配置文件路径

    -dir string [路径]变更程序的工作目录
    -dir2exe    变更程序的工作目录至可执行文件的目录

    -gen string [路径]生成一个配置文件模板至该路径
    -v          调试模式，更多的log输出
    -q          安静模式，无log
    -no-tcp     不监听tcp，只监听udp
    -no-udp     不监听udp，只监听tcp
    -cpu        使用CPU核数

## 更新大陆ip与域名表

`scripts\update_chn_ip_domain.py`能自动下载数据并生成大陆IP与域名列表`chn.list`，`chn_domain.list`到当前目录。

该脚本需要`python3`，依赖`netaddr`和`requests`。    

建议每两周更新一次。

## 分流效果

国内域名直接交由`local_server`解析，无格外延时，不会解析到国外。国际域名将会由`remote_server`解析，确保无污染。

<details><summary><code>dig www.baidu.com 演示</code></summary><br>

    ubuntu@ubuntu:~$ dig www.baidu.com @192.168.1.1 -p5455

    ; <<>> DiG 9.11.3-1ubuntu1.11-Ubuntu <<>> www.baidu.com @192.168.1.1 -p5455
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57335
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 4096
    ;; QUESTION SECTION:
    ;www.baidu.com.			IN	A

    ;; ANSWER SECTION:
    www.baidu.com.		561	IN	CNAME	www.a.shifen.com.
    www.a.shifen.com.	250	IN	A	36.152.44.96
    www.a.shifen.com.	250	IN	A	36.152.44.95

    ;; Query time: 4 msec
    ;; SERVER: 192.168.1.1#5455(192.168.1.1)
    ;; WHEN: Sun Mar 15 18:17:55 PDT 2020
    ;; MSG SIZE  rcvd: 149

</details>

<details><summary><code>dig www.google.com 演示</code></summary><br>

    ubuntu@ubuntu:~$ dig www.google.com @192.168.1.1 -p5455

    ; <<>> DiG 9.11.3-1ubuntu1.11-Ubuntu <<>> www.google.com @192.168.1.1 -p5455
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2719
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;www.google.com.			IN	A

    ;; ANSWER SECTION:
    www.google.com.		280	IN	A	74.125.68.99
    www.google.com.		280	IN	A	74.125.68.105
    www.google.com.		280	IN	A	74.125.68.104
    www.google.com.		280	IN	A	74.125.68.103
    www.google.com.		280	IN	A	74.125.68.106
    www.google.com.		280	IN	A	74.125.68.147

    ;; Query time: 72 msec
    ;; SERVER: 192.168.1.1#5455(192.168.1.1)
    ;; WHEN: Sun Mar 15 18:19:20 PDT 2020
    ;; MSG SIZE  rcvd: 223

</details>

## 和dnsmasq一起使用

mos-chinadns无缓存功能，dnsmasq可以用于缓存mos-chinadns的结果。

使用dnsmasq配合[dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)分流的方式很流行，但dnsmasq毕竟不是专为分流设计，其匹配域名的方式是逐一匹配，用时随列表长度线性增长。mos-chinadns自带的`chn_domain.list`包含[dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)中所有域名。不同的是，mos-chinadns采用hash算法匹配域名，处理[dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)包含的7万多条记录所需时间远远(几个数量级)小于dnsmasq。所以建议用mos-chinadns分流域名。

## 其他细节

**DNS-over-HTTPS (DoH)**

请求方式为[RFC 8484](https://tools.ietf.org/html/rfc8484) GET。

**请求流程与local_server黑/白/强制名单**

1. 如果指定了域名强制名单->匹配域名->
   1. 强制名单中的域名将发往`local_server`解析->接受返回结果->END
   2. 如果设定了`local_fdl_is_whitelist`->非强制名单中的域名将发往`remote_server`解析->接受返回结果->END
2. 如果指定了域名黑名单->匹配域名->黑名单中的域名将发往`remote_server`解析->接受返回结果->END
3. 同时发送至`local_server`与`remote_server`解析->
   1. `local_server`返回的空结果会被丢弃
   2. 如果指定了IP黑名单->匹配`local_server`返回的IP->丢弃黑名单中的结果
   3. 如果指定了IP白名单->匹配`local_server`返回的IP->丢弃不在白名单的结果
   4. 接受最先返回结果->END

简单的说：`local_server`的结果会根据设置进行过滤，`remote_server`的结果一定会被接受。
 
**域名黑/白名单格式**

采用按域向前匹配的方式。每个表达式一行。规则示例：

* `cn`会匹配所有以`.cn`结尾的域名和`cn`本身: `example.cn`，`www.google.cn`
* `google.com`会匹配所有以`.google.com`结尾的域名和`google.com`本身: `www.google.com`, `www.l.google.com`

比如：

    cn
    google.com
    google.com.hk
    www.google.com.sg

**IP黑/白名单格式**

由单个IP或CIDR构成，每个表达式一行，支持IPv6，比如：

    1.0.1.0/24
    2001:dd8:1a::/48

    2.2.2.2
    2001:ccd:1a

## 配置文件

    {
        // [IP:端口][必需] 监听地址。
        "bind_addr": "127.0.0.1:53", 

        // [IP:端口] `local_server`地址
        // 建议:一个低延时但会被污染的服务器，用于解析大陆域名。
        "local_server": "223.5.5.5:53",    

        // [URL] DoH服务器的url
        // 如果填入，`local_server`将使用DoH协议
        "local_server_url": "https://223.5.5.5/dns-query",

        // [path] 用于验证`local_server`的PEM格式CA证书的路径。
        // 默认使用系统证书池。
        "local_server_pem_ca": "/path/to/your/CA/cert",

        // [bool] `local_server`是否屏蔽非A或AAAA等不常见请求类型。
        "local_server_block_unusual_type": false,

        // [IP:端口] `remote_server`地址
        // 建议:一个无污染的服务器。用于解析国际域名。   
        "remote_server": "8.8.8.8:443", 

        // [URL] DoH服务器的url
        // 如果填入，`remote_server`将使用DoH协议。
        "remote_server_url": "https://dns.google/dns-query",  

        // [path] 用于验证`remote_server`的PEM格式CA证书的路径。
        // 默认使用系统证书池。
        "remote_server_pem_ca": "/path/to/your/CA/cert", 

        // [int] `remote_server`延时启动时间 单位:毫秒 
        // 如果在设定时间后`local_server`无响应，则开始请求`remote_server`。
        // `local_server`失败或结果被丢弃时，会中止等待立即开始请求`remote_server`。
        // 如果`local_server`延时较低，将该值设定为120%的`local_server`的延时可显著降低请求`remote_server`的次数。
        // 该选项主要用于缓解低运算力设备的压力。
        // 0表示禁用延时，请求将同时发送。
        "remote_server_delay_start": 0, 

        // [路径] `local_server`IP白名单
        // 建议:大陆IP列表，用于IP分流。
        "local_allowed_ip_list": "/path/to/your/chn/ip/list", 

        // [路径] `local_server`IP黑名单
        // 如果`local_server`返回黑名单中的IP，结果会被丢弃。
        // 建议:希望被屏蔽的IP列表，比如运营商的广告服务器IP。
        "local_blocked_ip_list": "/path/to/your/black/ip/list",
        
        // [路径] 强制使用`local_server`解析的域名名单
        // 这些域名只会被`local_server`解析。
        // 建议:大陆域名。
        "local_forced_domain_list": "/path/to/your/domain/list",

        // "local_forced_domain_list"是否是白名单
        // 如果true，不在其中的域名不会送至`local_server`解析。
        // 可对`local_server`屏蔽所有非国内域名请求，保护隐私。
        "local_fdl_is_whitelist": false,

        // [路径] `local_server`域名黑名单
        // 这些域名不会被`local_server`解析。
        // 建议:希望强制打开国际版而非国内版的域名。
        "local_blocked_domain_list": "/path/to/your/domain/list",

        // [CIDR] EDNS Client Subnet
        // 如果填入，如果下游请求未包含ECS，发出至`local/remote_server`的请求会附带上此IP段。
        "local_ecs_subnet": "1.2.3.0/24",
        "remote_ecs_subnet": "3.2.1.0/24"       
    }

## Open Source Components / Libraries / Reference

部分设计参考

* [ChinaDNS](https://github.com/shadowsocks/ChinaDNS): [GPLv3](https://github.com/shadowsocks/ChinaDNS/blob/master/COPYING)

依赖

* [sirupsen/logrus](https://github.com/sirupsen/logrus): [MIT](https://github.com/sirupsen/logrus/blob/master/LICENSE)
* [miekg/dns](https://github.com/miekg/dns): [LICENSE](https://github.com/miekg/dns/blob/master/LICENSE)
* [valyala/fasthttp](https://github.com/valyala/fasthttp):[MIT](https://github.com/valyala/fasthttp/blob/master/LICENSE)

资源

* `chn_domain.list`数据来自: [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list): [LICENSE](https://github.com/felixonmars/dnsmasq-china-list/blob/master/LICENSE)
* `chn.list`数据来自: [APNIC](https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest)