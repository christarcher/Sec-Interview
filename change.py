#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re

# 文件夹重命名映射表
FOLDER_RENAME_MAP = {
    "Chapter1": "Chapter01_信息收集",
    "Chapter2": "Chapter02_XSS",
    "Chapter3": "Chapter03_CSRF",
    "Chapter4": "Chapter04_SQL注入",
    "Chapter5": "Chapter05_横向移动",
    "Chapter6": "Chapter06_中间件",
    "Chapter7": "Chapter07_蓝队防守",
    "Chapter8": "Chapter08_内网穿透",
    "Chapter9": "Chapter09_权限维持",
    "Chapter10": "Chapter10_SSRF",
    "Chapter11": "Chapter11_XXE",
    "Chapter12": "Chapter12_文件上传漏洞",
    "Chapter13": "Chapter13_RCE",
    "Chapter14": "Chapter14_反序列化漏洞",
    "Chapter15": "Chapter15_权限提升",
    "Chapter16": "Chapter16_文件包含漏洞",
    "Chapter17": "Chapter17_MongoDB注入",
    "Chapter18": "Chapter18_CORS",
    "Chapter19": "Chapter19_远控免杀",
    "Chapter20": "Chapter20_PHP代码审计",
    "Chapter21": "Chapter21_JAVA代码审计",
    "Chapter22": "Chapter22_操作系统",
    "Chapter23": "Chapter23_逆向破解",
    "Chapter24": "Chapter24_痕迹清除",
    "Chapter25": "Chapter25_钓鱼社工",
    "Chapter26": "Chapter26_二进制",
    "Chapter27": "Chapter27_AI安全",
    "Chapter28": "Chapter28_密码学安全",
    "Chapter29": "Chapter29_区块链安全",
    "Chapter30": "Chapter30_云安全",
    "Chapter31": "Chapter31_APP安全",
}

# 目录映射表 - 根据SUMMARY.md内容生成
RENAME_MAP = {
    "Chapter1": {
        "1-1.md": "1-1_如何处理子域名爆破的泛解析问题.md",
        "1-2.md": "1-2_如何绕过CDN查找真实IP.md",
        "1-3.md": "1-3_phpinfo页面你会关注哪些信息.md",
        "1-4.md": "1-4_如何判断目标操作系统.md",
        "1-5.md": "1-5_如何判断是否使用CDN.md",
        "1-6.md": "1-6_SVN_GIT源代码泄露.md",
        "1-7.md": "1-7_域信息收集思路.md",
        "1-8.md": "1-8_如何快速定位域控.md",
        "1-9.md": "1-9_Wappalyzer指纹识别原理.md",
        "1-10.md": "1-10_登录验证码怎么绕过.md",
        "1-11.md": "1-11_工作组环境下怎么判断是否有域环境.md",
        "1-12.md": "1-12_只有一个网卡如何判断内网是否有其他网段.md",
        "1-13.md": "1-13_Webpack信息泄露.md",
        "1-14.md": "1-14_net_group查询域管理员没查到的问题.md",
        "1-15.md": "1-15_net_group命令的本质.md",
        "1-16.md": "1-16_如何判断目标单位机器哪种协议出网.md",
        "1-17.md": "1-17_NSE脚本原理.md",
        "1-18.md": "1-18_Nmap的FIN扫描和空扫描.md",
    },
    "Chapter2": {
        "2-1.md": "2-1_输出到href属性的XSS如何防御.md",
        "2-2.md": "2-2_XSS绕过方式.md",
        "2-3.md": "2-3_XSS利用方式.md",
        "2-4.md": "2-4_XSS怎么打内网.md",
        "2-5.md": "2-5_XSS如何绕过HttpOnly获取Cookie.md",
        "2-6.md": "2-6_有Shell的情况下如何使用XSS实现长久控制.md",
    },
    "Chapter3": {
        "3-1.md": "3-1_SameSite防御CSRF的原理.md",
        "3-2.md": "3-2_JSON格式的CSRF如何防御.md",
        "3-3.md": "3-3_Ajax发送POST请求会发几个数据包.md",
    },
    "Chapter4": {
        "4-2.md": "4-2_SQL报错注入函数有哪些.md",
        "4-3.md": "4-3_SQL延时盲注sleep被禁用怎么绕过.md",
        "4-4.md": "4-4_SQL注入怎么写入WebShell.md",
        "4-5.md": "4-5_宽字节注入漏洞原理.md",
        "4-6.md": "4-6_二次注入漏洞原理.md",
        "4-7.md": "4-7_堆叠注入漏洞原理.md",
        "4-8.md": "4-8_SQLMap参数level与risk区别.md",
        "4-9.md": "4-9_MySQL提权方式有哪些.md",
        "4-10.md": "4-10_MSSQL的xp_cmdshell被禁用怎么绕过.md",
        "4-11.md": "4-11_MySQL5.0以上和5.0以下的区别.md",
        "4-12.md": "4-12_SQL注入outfile被过滤怎么绕过.md",
        "4-13.md": "4-13_SQL注入Post和Get都防注入的绕过.md",
        "4-14.md": "4-14_SQL盲注if函数被过滤怎么绕过.md",
        "4-15.md": "4-15_SQL注入无回显利用DNSLog构造.md",
        "4-16.md": "4-16_and_or被过滤怎么绕过.md",
        "4-17.md": "4-17_SQLMap自带脚本有哪些.md",
        "4-18.md": "4-18_扫出asp数据库文件访问乱码如何利用.md",
        "4-19.md": "4-19_找到注入点怎么判断数据库类型.md",
        "4-20.md": "4-20_单引号被过滤怎么绕过.md",
        "4-21.md": "4-21_MySQL一个@和两个@的区别.md",
        "4-22.md": "4-22_为什么MSSQL存储过程可以执行命令.md",
        "4-23.md": "4-23_MSSQL上传文件需要开启哪个存储过程权限.md",
    },
    "Chapter5": {
        "5-2.md": "5-2_CS上线不出网机器用什么类型Beacon.md",
        "5-3.md": "5-3_PTT有哪些攻击方法.md",
        "5-4.md": "5-4_DCSync的利用条件.md",
        "5-5.md": "5-5_横向渗透命令执行手段.md",
        "5-6.md": "5-6_PTH_PTT_PTK三者区别.md",
        "5-7.md": "5-7_机器不出网如何传输exe文件.md",
        "5-8.md": "5-8_域内委派.md",
        "5-9.md": "5-9_怎么定位域管曾经登录哪些机器.md",
        "5-10.md": "5-10_域外工作组机器如何进入域中找到域控.md",
        "5-11.md": "5-11_NTLM_Relay配合ADCS漏洞需要什么条件.md",
        "5-12.md": "5-12_Responder应该开在哪台机器上.md",
        "5-13.md": "5-13_ADCS漏洞获取域管权限的原理.md",
        "5-14.md": "5-14_拿到vCenter权限如何深入利用.md",
        "5-15.md": "5-15_拿到vCenter管理员权限虚拟机锁屏怎么办.md",
        "5-16.md": "5-16_Kerberos的原理.md",
        "5-17.md": "5-17_Flannel_Calico_Cilium的区别.md",
    },
    "Chapter6": {
        "6-1.md": "6-1_Fastjson漏洞原理.md",
        "6-2.md": "6-2_Log4j漏洞原理.md",
        "6-4.md": "6-4_Shiro550_721区别.md",
        "6-5.md": "6-5_FastJSON不出网利用方式.md",
        "6-6.md": "6-6_Windows和Linux利用REDIS的区别.md",
        "6-7.md": "6-7_Nginx_CRLF注入原理.md",
        "6-8.md": "6-8_如何判断靶标是否使用FastJSON.md",
        "6-9.md": "6-9_如何判断靶标是否使用Log4j.md",
        "6-10.md": "6-10_如何判断靶标是否使用Shiro.md",
        "6-11.md": "6-11_Nacos如何通过配置文件拿Shell.md",
        "6-12.md": "6-12_Nacos不出网利用方式.md",
        "6-13.md": "6-13_do文件是哪种框架.md",
        "6-14.md": "6-14_Shiro有Key无链怎么利用.md",
        "6-15.md": "6-15_Redis主从复制原理.md",
        "6-16.md": "6-16_phpMyAdmin写Shell的方法.md",
        "6-17.md": "6-17_中间件解析漏洞.md",
        "6-18.md": "6-18_Shiro不出网怎么利用.md",
        "6-19.md": "6-19_JNDI的解析流程和原理.md",
        "6-20.md": "6-20_runc容器逃逸原理.md",
        "6-21.md": "6-21_JBoss反序列化漏洞原理.md",
        "6-22.md": "6-22_XStream反序列化漏洞原理.md",
        "6-23.md": "6-23_Confluence_RCE.md",
        "6-24.md": "6-24_Spring相关的RCE原理.md",
        "6-25.md": "6-25_Log4j如何绕过trustURLCodebase.md",
        "6-26.md": "6-26_Fastjson文件读写gadget原理.md",
        "6-27.md": "6-27_Spring4shell原理检测利用.md",
        "6-28.md": "6-28_Kubernetes攻击思路.md",
    },
    "Chapter7": {
        "7-1.md": "7-1_内存马查杀思路.md",
        "7-2.md": "7-2_Linux日志存放位置.md",
        "7-3.md": "7-3_常见Windows事件ID.md",
        "7-4.md": "7-4_aspx木马权限比asp木马权限更高的原因.md",
        "7-5.md": "7-5_如何判断Log4j攻击成功.md",
        "7-6.md": "7-6_告警内网IP如何快速定位物理位置.md",
        "7-7.md": "7-7_SQL注入防御方法.md",
        "7-8.md": "7-8_数万条告警怎么快速找到攻击成功的.md",
        "7-9.md": "7-9_WebShell查杀后仍有流量怎么办.md",
        "7-10.md": "7-10_拿到攻击者IP怎么溯源.md",
        "7-11.md": "7-11_内网报警处理方式.md",
        "7-12.md": "7-12_怎样从日志找WebShell位置.md",
        "7-13.md": "7-13_常见日志分析工具.md",
        "7-14.md": "7-14_网页挂马排查思路.md",
        "7-15.md": "7-15_XSS防御方法.md",
        "7-16.md": "7-16_CSRF防御方法.md",
        "7-17.md": "7-17_SSRF防御方法.md",
        "7-18.md": "7-18_XXE防御方法.md",
        "7-19.md": "7-19_文件上传防御方法.md",
        "7-20.md": "7-20_CS流量特征.md",
        "7-21.md": "7-21_WebShell工具流量特征.md",
        "7-22.md": "7-22_日志被删除如何排查.md",
        "7-23.md": "7-23_常见加固手段.md",
        "7-24.md": "7-24_挖矿病毒特征.md",
        "7-25.md": "7-25_挖矿病毒应急思路.md",
        "7-26.md": "7-26_如何判断钓鱼邮件.md",
        "7-27.md": "7-27_暴露面梳理怎么做.md",
        "7-28.md": "7-28_netstat和ss命令的区别.md",
        "7-29.md": "7-29_Windows日志存储位置.md",
        "7-30.md": "7-30_云产品的应急思路.md",
        "7-31.md": "7-31_DNS重绑定漏洞原理.md",
        "7-32.md": "7-32_Token和Referer的安全等级谁高.md",
        "7-33.md": "7-33_任意文件下载漏洞防御方法.md",
        "7-34.md": "7-34_怎么修改TTL值.md",
        "7-35.md": "7-35_Linux怎么查看程序调用了哪些文件.md",
        "7-36.md": "7-36_CMD如何查询远程终端开放端口.md",
        "7-37.md": "7-37_查看服务器可疑账号新增账号.md",
        "7-38.md": "7-38_查看服务器隐藏账号克隆账号.md",
        "7-39.md": "7-39_SQL注入转义字符防御遇到特殊字符怎么办.md",
        "7-40.md": "7-40_哪些SQL语句无法使用预编译.md",
        "7-41.md": "7-41_SYN开放链接原理.md",
        "7-42.md": "7-42_Linux_proc目录.md",
        "7-43.md": "7-43_如何监控Linux文件操作.md",
        "7-44.md": "7-44_Windows_Defender安全机制.md",
        "7-45.md": "7-45_TCP粘包拆包.md",
        "7-46.md": "7-46_session的工作原理.md",
        "7-47.md": "7-47_HTTP长连接和短连接的区别.md",
        "7-48.md": "7-48_Xrange和range返回的是什么.md",
        "7-49.md": "7-49_怎么防重放攻击.md",
        "7-50.md": "7-50_SYN_FLOOD原理防御检测.md",
        "7-51.md": "7-51_UDP反射放大的原理防御检测.md",
    },
    "Chapter8": {
        "8-1.md": "8-1_正向代理和反向代理区别.md",
        "8-2.md": "8-2_如何进行内网穿透.md",
        "8-3.md": "8-3_如何隐藏CS流量.md",
        "8-4.md": "8-4_ICMP隧道的流量特征.md",
        "8-5.md": "8-5_代理转发常用的工具.md",
        "8-6.md": "8-6_Ping不通外网如何搭建隧道.md",
        "8-7.md": "8-7_内网的多级代理用什么代理.md",
        "8-8.md": "8-8_TCP和UDP不出网怎么绕过.md",
        "8-9.md": "8-9_多级代理如何做CDN中转.md",
        "8-10.md": "8-10_内网ACL白名单策略如何绕过.md",
    },
    "Chapter9": {
        "9-1.md": "9-1_怎么建立隐藏用户.md",
        "9-2.md": "9-2_360晶核模式怎么权限维持.md",
        "9-3.md": "9-3_计划任务被拦截了怎么办.md",
    },
    "Chapter10": {
        "10-1.md": "10-1_SSRF漏洞存在位置.md",
        "10-2.md": "10-2_SSRF漏洞绕过方法.md",
        "10-3.md": "10-3_SSRF漏洞利用方式.md",
        "10-4.md": "10-4_SSRF如何攻击内网服务.md",
        "10-5.md": "10-5_如何判断SSRF流量是否攻击成功.md",
        "10-6.md": "10-6_SSRF怎么用Redis写Shell.md",
    },
    "Chapter11": {
        "11-1.md": "11-1_XXE漏洞利用方式.md",
        "11-2.md": "11-2_XXE盲注思路.md",
        "11-3.md": "11-3_PCDATA和CDATA的区别.md",
    },
    "Chapter12": {
        "12-1.md": "12-1_文件上传漏洞绕过方法.md",
    },
    "Chapter13": {
        "13-1.md": "13-1_代码执行命令执行的函数.md",
        "13-2.md": "13-2_正向Shell和反向Shell区别.md",
        "13-3.md": "13-3_非交互Shell提升为交互Shell.md",
        "13-4.md": "13-4_PHP_disable_functions绕过方法.md",
        "13-5.md": "13-5_PHP的00截断原理.md",
        "13-6.md": "13-6_站库分离怎么拿Shell.md",
    },
    "Chapter14": {
        "14-1.md": "14-1_CC1_CC6区别.md",
        "14-2.md": "14-2_CC1-7的原理.md",
        "14-3.md": "14-3_BCEL利用链使用条件及原理.md",
        "14-4.md": "14-4_BCEL可以用其他类加载器吗.md",
        "14-5.md": "14-5_JEP290的原理.md",
        "14-6.md": "14-6_RMI原理以及相关的漏洞.md",
        "14-7.md": "14-7_JdbcRowSetImpl如何触发JNDI注入.md",
        "14-8.md": "14-8_CC链四个Transformer区别.md",
        "14-9.md": "14-9_反序列化除了readObject还有什么触发点.md",
        "14-10.md": "14-10_IIOP和T3反序列化原理.md",
        "14-11.md": "14-11_Java_invoke反射具体利用.md",
    },
    "Chapter15": {
        "15-1.md": "15-1_LM_Hash加密算法过程.md",
        "15-2.md": "15-2_与SMB协议相关的漏洞.md",
        "15-3.md": "15-3_脏牛漏洞提权原理.md",
        "15-4.md": "15-4_黄金票据和白银票据区别.md",
        "15-5.md": "15-5_读取不到hash怎么绕过.md",
        "15-6.md": "15-6_Windows_Server_2008如何提权.md",
        "15-7.md": "15-7_提权时选择可读写目录不用带空格目录.md",
        "15-8.md": "15-8_只能通过命令行执行的Shell怎么办.md",
        "15-9.md": "15-9_psexec和wmic区别.md",
        "15-10.md": "15-10_内网抓取密码.md",
        "15-11.md": "15-11_内网有杀软怎么抓密码.md",
        "15-12.md": "15-12_操作系统什么版本后抓不到密码.md",
        "15-13.md": "15-13_抓不到密码怎么绕过.md",
        "15-14.md": "15-14_桌面有管理员会话怎么会话劫持.md",
        "15-15.md": "15-15_当前机器有加密密码本怎么办.md",
        "15-16.md": "15-16_Dcom怎么操作.md",
        "15-17.md": "15-17_获取域控的方法.md",
        "15-18.md": "15-18_DLL劫持原理.md",
        "15-19.md": "15-19_DPAPI机制能干嘛.md",
        "15-20.md": "15-20_MS14-068原理.md",
        "15-21.md": "15-21_内网文件exe落地用什么命令执行.md",
        "15-22.md": "15-22_DB文件如何解密及原理.md",
        "15-23.md": "15-23_PTH中LM_hash和NTLM_hash的区别.md",
        "15-24.md": "15-24_Print_Nightmare漏洞分析.md",
        "15-25.md": "15-25_CS域前置的原理.md",
        "15-26.md": "15-26_CS流量通信方式.md",
    },
    "Chapter16": {
        "16-1.md": "16-1_文件包含常用的协议.md",
        "16-2.md": "16-2_文件包含怎么GetShell.md",
    },
    "Chapter17": {
        "17-1.md": "17-1_MongoDB注入方式.md",
    },
    "Chapter18": {
        "18-1.md": "18-1_CORS利用方式.md",
    },
    "Chapter19": {
        "19-1.md": "19-1_ShellCode免杀方法.md",
        "19-2.md": "19-2_如何过国内杀软.md",
        "19-3.md": "19-3_分离免杀和单体免杀区别.md",
        "19-4.md": "19-4_CS和MSF结合免杀.md",
    },
    "Chapter20": {
        "20-1.md": "20-1_PHP三等号和双等号区别.md",
        "20-2.md": "20-2_常见入口函数怎么找.md",
        "20-3.md": "20-3_PHP代码审计流程.md",
        "20-4.md": "20-4_ThinkPHP框架审计有什么不同.md",
        "20-5.md": "20-5_PHP原生的敏感函数.md",
        "20-6.md": "20-6_反序列化魔术方法入手点.md",
        "20-7.md": "20-7_常见的路由方法.md",
        "20-8.md": "20-8_PHP的变量覆盖.md",
        "20-9.md": "20-9_远程文件包含和本地文件包含的PHP设置.md",
        "20-10.md": "20-10_本地文件包含能否限制文件包含路径.md",
        "20-11.md": "20-11_PHP做SQL注入防御的方法.md",
        "20-12.md": "20-12_审计到文件下载漏洞如何深入利用.md",
        "20-13.md": "20-13_Fortify等代码审计工具原理.md",
    },
    "Chapter21": {
        "21-1.md": "21-1_JAVA做SQL注入防御的方法.md",
    },
    "Chapter22": {
        "22-1.md": "22-1_进程和线程内存空间的关系.md",
        "22-2.md": "22-2_父子进程.md",
        "22-3.md": "22-3_孤儿进程和僵尸进程区别.md",
        "22-4.md": "22-4_Kill进程从父子进程角度讲发生了什么.md",
        "22-5.md": "22-5_Linux开机自启动方式.md",
        "22-6.md": "22-6_Linux系统调用.md",
        "22-7.md": "22-7_Linux下的Syscall.md",
    },
    "Chapter23": {
        "23-1.md": "23-1_恶意样本函数家族md5分类.md",
        "23-2.md": "23-2_Linux程序分为哪几个段.md",
        "23-3.md": "23-3_data段存放哪些数据.md",
        "23-4.md": "23-4_bss段存放哪些数据.md",
        "23-5.md": "23-5_函数调用时的流程参数传入及寄存器栈的变化.md",
        "23-6.md": "23-6_程序的编译和链接.md",
        "23-7.md": "23-7_If_Else语法树.md",
        "23-8.md": "23-8_如何比较两个C函数的相似度.md",
        "23-9.md": "23-9_源代码与IDA反编译代码差别大的情况.md",
        "23-10.md": "23-10_静态编译大型木马如何定位网络传输逻辑.md",
        "23-11.md": "23-11_如何动态地去找导入表.md",
        "23-12.md": "23-12_不导入API前提下如何进行攻击.md",
        "23-13.md": "23-13_Windows常用的反调试技术.md",
        "23-14.md": "23-14_单步执行的原理.md",
        "23-15.md": "23-15_内存中已Load程序如何快速找执行权限段.md",
        "23-16.md": "23-16_恶意软件检测沙箱的方案.md",
        "23-17.md": "23-17_做反汇编器指令集opcode去哪查.md",
        "23-18.md": "23-18_怎么识别指令跳转条件和内存访问.md",
        "23-19.md": "23-19_做沙箱有什么需要重定向的.md",
        "23-20.md": "23-20_ESP定律原理.md",
        "23-21.md": "23-21_C++程序逆向找虚表.md",
        "23-22.md": "23-22_进程隐藏技术及检测.md",
        "23-23.md": "23-23_多进程下Source触发Sink点如何溯源.md",
        "23-24.md": "23-24_JNDI如何做Hook.md",
    },
    "Chapter24": {
        "24-1.md": "24-1_清理日志要清理哪些.md",
        "24-2.md": "24-2_如何删除Linux机器的入侵痕迹.md",
    },
    "Chapter25": {
        "25-1.md": "25-1_钓鱼方法除了exe还有什么.md",
        "25-2.md": "25-2_钓鱼上线的主机如何利用.md",
        "25-3.md": "25-3_伪造电子邮件的原理.md",
    },
    "Chapter26": {
        "26-1.md": "26-1_工控场景入侵检测与普通场景区别.md",
        "26-2.md": "26-2_Linux平台的漏洞缓解机制.md",
        "26-3.md": "26-3_NX如何绕过.md",
        "26-4.md": "26-4_Linux平台的ELF文件结构.md",
        "26-5.md": "26-5_Windows平台的PE文件结构.md",
        "26-6.md": "26-6_ASLR怎么绕过.md",
        "26-7.md": "26-7_函数的调用约定及区别.md",
        "26-8.md": "26-8_fuzzing主要用来干嘛.md",
        "26-9.md": "26-9_Windows平台的漏洞和保护机制.md",
        "26-10.md": "26-10_QEMU模式和源码模式Fuzzing对比.md",
        "26-11.md": "26-11_QEMU模式动态插桩实现及优缺点.md",
        "26-12.md": "26-12_fuzz普通程序和数据库的不同点.md",
        "26-13.md": "26-13_AFL++和AFL有哪些不同.md",
        "26-14.md": "26-14_怎么给AFL做适配去fuzz数据库.md",
        "26-15.md": "26-15_fuzz的流程从选取目标开始.md",
        "26-16.md": "26-16_AFL的插桩原理.md",
        "26-17.md": "26-17_怎么选择fuzz测试点.md",
        "26-18.md": "26-18_哪些漏洞可以用fuzz检测到.md",
        "26-19.md": "26-19_符号执行如何做约束求解.md",
    },
    "Chapter27": {
        "27-1.md": "27-1_SVM介绍.md",
        "27-2.md": "27-2_KNN介绍.md",
        "27-3.md": "27-3_卷积神经网络介绍.md",
        "27-4.md": "27-4_莱文斯坦距离.md",
        "27-5.md": "27-5_倒排索引.md",
        "27-6.md": "27-6_搜索引擎的算法.md",
        "27-7.md": "27-7_TF-IDF文档匹配算法.md",
        "27-8.md": "27-8_SGD和Adam的区别.md",
        "27-9.md": "27-9_如何缩减模型的检测时延.md",
        "27-10.md": "27-10_如何降低模型的误报率.md",
        "27-11.md": "27-11_如何找攻击样本.md",
    },
    "Chapter28": {
        "28-1.md": "28-1_RSA算法原理.md",
        "28-2.md": "28-2_AES算法原理.md",
        "28-3.md": "28-3_非对称加密算法的加密过程.md",
        "28-4.md": "28-4_了解过的非对称加密算法.md",
        "28-5.md": "28-5_栅栏密码的原理.md",
        "28-6.md": "28-6_Padding_Oracle_Attack.md",
    },
    "Chapter29": {
        "29-1.md": "29-1_交易所.md",
        "29-2.md": "29-2_区块链逆向函数接收参数的指令集.md",
        "29-3.md": "29-3_重入漏洞.md",
        "29-4.md": "29-4_DeFi项目中经济模型漏洞挖掘.md",
        "29-5.md": "29-5_libsnark核心.md",
        "29-6.md": "29-6_truffle_solidity.md",
        "29-7.md": "29-7_智能合约的鉴权公私密钥.md",
        "29-8.md": "29-8_数字钱包的身份认证.md",
    },
    "Chapter30": {
        "30-1.md": "30-1_控制云主机但没有内网如何利用.md",
    },
    "Chapter31": {
        "31-1.md": "31-1_安卓系统RCE思路.md",
        "31-2.md": "31-2_移动端APP服务端是cloud环境利用思路.md",
    },
}


def rename_folders(base_path="./Sec-Interview"):
    """
    重命名文件夹
    :param base_path: 项目根目录路径
    """
    renamed_count = 0
    error_count = 0
    
    print("开始重命名文件夹...\n")
    
    for old_name, new_name in FOLDER_RENAME_MAP.items():
        old_path = os.path.join(base_path, old_name)
        new_path = os.path.join(base_path, new_name)
        
        # 检查源文件夹是否存在
        if not os.path.exists(old_path):
            print(f"  跳过: {old_name} (文件夹不存在)")
            continue
        
        # 检查目标文件夹是否已存在
        if os.path.exists(new_path):
            print(f"  跳过: {old_name} -> {new_name} (目标文件夹已存在)")
            continue
        
        try:
            os.rename(old_path, new_path)
            print(f"  ✓ {old_name} -> {new_name}")
            renamed_count += 1
        except Exception as e:
            print(f"  ✗ 重命名失败: {old_name} -> {new_name}")
            print(f"    错误: {str(e)}")
            error_count += 1
    
    print(f"\n文件夹重命名完成!")
    print(f"成功: {renamed_count} 个文件夹")
    print(f"失败: {error_count} 个文件夹\n")


def rename_files(base_path="./Sec-Interview"):
    """
    重命名文件（使用新的文件夹名）
    :param base_path: 项目根目录路径
    """
    renamed_count = 0
    error_count = 0
    
    print("开始重命名文件...\n")
    
    for old_folder, new_folder in FOLDER_RENAME_MAP.items():
        # 使用新的文件夹名
        chapter_path = os.path.join(base_path, new_folder)
        
        if not os.path.exists(chapter_path):
            # 如果新文件夹不存在，尝试使用旧文件夹名
            chapter_path = os.path.join(base_path, old_folder)
            if not os.path.exists(chapter_path):
                print(f"警告: 目录 {old_folder}/{new_folder} 都不存在，跳过")
                continue
        
        # 获取对应章节的文件映射
        if old_folder not in RENAME_MAP:
            continue
            
        files = RENAME_MAP[old_folder]
        print(f"处理章节: {new_folder}")
        
        for old_name, new_name in files.items():
            old_path = os.path.join(chapter_path, old_name)
            new_path = os.path.join(chapter_path, new_name)
            
            # 检查源文件是否存在
            if not os.path.exists(old_path):
                print(f"  跳过: {old_name} (文件不存在)")
                continue
            
            # 检查目标文件是否已存在
            if os.path.exists(new_path):
                print(f"  跳过: {old_name} -> {new_name} (目标文件已存在)")
                continue
            
            try:
                os.rename(old_path, new_path)
                print(f"  ✓ {old_name} -> {new_name}")
                renamed_count += 1
            except Exception as e:
                print(f"  ✗ 重命名失败: {old_name} -> {new_name}")
                print(f"    错误: {str(e)}")
                error_count += 1
        
        print()
    
    print(f"文件重命名完成!")
    print(f"成功: {renamed_count} 个文件")
    print(f"失败: {error_count} 个文件")


def preview_changes(base_path="./Sec-Interview"):
    """
    预览将要进行的重命名操作，不实际执行
    :param base_path: 项目根目录路径
    """
    print("=" * 60)
    print("预览重命名操作")
    print("=" * 60)
    
    print("\n【第一步：文件夹重命名】\n")
    folder_count = 0
    for old_name, new_name in FOLDER_RENAME_MAP.items():
        old_path = os.path.join(base_path, old_name)
        if os.path.exists(old_path):
            print(f"  {old_name} -> {new_name}")
            folder_count += 1
        else:
            print(f"  {old_name} (不存在)")
    
    print(f"\n总共将重命名 {folder_count} 个文件夹\n")
    
    print("\n【第二步：文件重命名】\n")
    total_count = 0
    for old_folder, new_folder in FOLDER_RENAME_MAP.items():
        chapter_path = os.path.join(base_path, old_folder)
        
        if old_folder not in RENAME_MAP:
            continue
            
        files = RENAME_MAP[old_folder]
        print(f"{new_folder}:")
        
        for old_name, new_name in files.items():
            old_path = os.path.join(chapter_path, old_name)
            if os.path.exists(old_path):
                print(f"  {old_name} -> {new_name}")
                total_count += 1
            else:
                print(f"  {old_name} (不存在)")
        print()
    
    print(f"总共将重命名 {total_count} 个文件")
    print("=" * 60)


def rename_all(base_path="./Sec-Interview"):
    """
    执行完整的重命名流程：先重命名文件夹，再重命名文件
    :param base_path: 项目根目录路径
    """
    print("=" * 60)
    print("开始执行完整重命名流程")
    print("=" * 60)
    print()
    
    # 第一步：重命名文件夹
    rename_folders(base_path)
    
    # 第二步：重命名文件
    rename_files(base_path)
    
    print("=" * 60)
    print("所有重命名操作完成！")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    
    # 默认路径，可以根据实际情况修改
    project_path = "./Sec-Interview"
    
    # 检查命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == "--preview":
            preview_changes(project_path)
        elif sys.argv[1] == "--folders-only":
            # 只重命名文件夹
            confirm = input(f"即将重命名 {project_path} 目录下的文件夹，是否继续? (y/n): ")
            if confirm.lower() == 'y':
                rename_folders(project_path)
            else:
                print("操作已取消")
        elif sys.argv[1] == "--files-only":
            # 只重命名文件
            confirm = input(f"即将重命名 {project_path} 目录下的文件，是否继续? (y/n): ")
            if confirm.lower() == 'y':
                rename_files(project_path)
            else:
                print("操作已取消")
        elif sys.argv[1] == "--help":
            print("用法:")
            print("  python rename_files.py                # 执行完整重命名（文件夹+文件）")
            print("  python rename_files.py --preview      # 预览重命名操作")
            print("  python rename_files.py --folders-only # 只重命名文件夹")
            print("  python rename_files.py --files-only   # 只重命名文件")
            print("  python rename_files.py --help         # 显示帮助信息")
            print("  python rename_files.py <path>         # 指定项目路径")
        else:
            project_path = sys.argv[1]
            confirm = input(f"即将重命名 {project_path} 目录，是否继续? (y/n): ")
            if confirm.lower() == 'y':
                rename_all(project_path)
            else:
                print("操作已取消")
    else:
        # 默认执行完整重命名
        confirm = input(f"即将重命名 {project_path} 目录下的文件夹和文件，是否继续? (y/n): ")
        if confirm.lower() == 'y':
            rename_all(project_path)
        else:
            print("操作已取消")
