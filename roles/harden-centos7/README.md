add
本加固脚本参考如下文档，存在出入。

目录
------------

一、用户帐号和环境
二、系统访问认证和授权
三、核心调整
四、关闭不必要服务
五、SSH安全配置
六、启用系统审计服务
七、部署完整性检查工具软件
八、开启防火墙策略
九、安全启动
十、日志服务器
十一、备份

一、用户帐号和环境
------------

1	清除了operator、lp、shutdown、halt、games、gopher 帐号
删除的用户组有： lp、uucp、games、dip
其它系统伪帐号均处于锁定SHELL登录的状态

2	验证是否有账号存在空口令的情况:
awk -F: '($2 == "") { print $1 }' /etc/shadow

3	检查除了root以外是否还有其它账号的UID为0:
awk -F: '($3 == 0) { print $1 }' /etc/passwd 任何UID为0的账号在系统上都具有超级用户权限.

4	检查root用户的$PATH中是否有’.’或者所有用户/组用户可写的目录	超级用户的$PATH设置中如果存在这些目录可能会导致超级用户误执行一个特洛伊木马

5	用户的home目录许可权限设置为700	用户home目录的许可权限限制不严可能会导致恶意用户读/修改/删除其它用户的数据或取得其它用户的系统权限

6	是否有用户的点文件是所有用户可读写的:
for dir in \
`awk -F: '($3 >= 500) { print $6 }' /etc/passwd`
do
for file in $dir/.[A-Za-z0-9]*
do
if [ -f $file ]; then
chmod o-w $file
fi
done
done
	Unix/Linux下通常以”.”开头的文件是用户的配置文件,如果存在所有用户可读/写的配置文件可能会使恶意用户能读/写其它用户的数据或取得其它用户的系统权限

7	为用户设置合适的缺省umask值:
cd /etc
for file in profile csh.login csh.cshrc bashrc
do
if [ `grep -c umask $file` -eq 0 ];
then
echo "umask 022" >> $file
fi
chown root:root $file
chmod 444 $file
done

8	设备系统口令策略：修改/etc/login.defs文件,将PASS_MIN_LEN最小密码长度设置为12位。

9	限制能够su为root 的用户：#vi /etc/pam.d/su
在文件头部添加下面这样的一行
auth           required        pam_wheel.so use_uid	这样，只有wheel组的用户可以su到root


10	修改别名文件/etc/aliases：#vi /etc/aliases
注释掉不要的 #games: root #ingres: root #system: root #toor: root #uucp: root #manager: root #dumper: root #operator: root #decode: root #root: marc
修改后执行/usr/bin/newaliases

11	修改帐户TMOUT值，设置自动注销时间
vi /etc/profile
增加TMOUT=600 	无操作600秒后自动退出

12	设置Bash保留历史命令的条数
#vi /etc/profile
修改HISTSIZE=99999	即只保留最新执行的99999条命令

13	防止IP SPOOF：
#vi /etc/host.conf 添加：nospoof on	不允许服务器对IP地址进行欺骗

二、系统访问认证和授权
------------

1	限制 at/cron给授权的用户:
cd /etc/
rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
chown root:root cron.allow at.allow
chmod 400 cron.allow at.allow
	Cron.allow和at.allow文件列出了允许允许crontab和at命令的用户名单, 在多数系统上通常只有系统管理员才需要运行这些命令

2	Crontab文件限制访问权限:
chown root:root /etc/crontab
chmod 400 /etc/crontab
chown -R root:root /var/spool/cron
chmod -R go-rwx /var/spool/cron
chown -R root:root /etc/cron.*
chmod -R go-rwx /etc/cron.*
	系统的crontab文件应该只能被cron守护进程(它以超级用户身份运行)来访问,一个普通用户可以修改crontab文件会导致他可以以超级用户身份执行任意程序

3	建立恰当的警告banner:
echo "Authorized uses only. All activity may be \
monitored and reported." >>/etc/motd
chown root:root /etc/motd
chmod 644 /etc/motd
echo "Authorized uses only. All activity may be \
monitored and reported." >> /etc/issue
echo "Authorized uses only. All activity may be \
monitored and reported." >> /etc/issue.net	改变登录banner可以隐藏操作系统类型和版本号和其它系统信息,这些信息可以会对攻击者有用.

4	限制root登录到系统控制台:
cat <<END_FILE >/etc/securetty
tty1
tty2
tty3
tty4
tty5
tty6
END_FILE
chown root:root /etc/securetty
chmod 400 /etc/securetty
	通常应该以普通用户身份访问系统,然后通过其它授权机制(比如su命令和sudo)来获得更高权限,这样做至少可以对登录事件进行跟踪

5	设置守护进程掩码
vi /etc/rc.d/init.d/functions
设置为 umask 022	系统缺省的umask 值应该设定为022以避免守护进程创建所有用户可写的文件

6	用户SSH登陆通过yubikey
操作员连接钱包机器使用windows运维机，配置yubikey+GPG模式


三、核心调整
------------

1	禁止core dump:
cat <<END_ENTRIES >>/etc/security/limits.conf
* soft core 0
* hard core 0
END_ENTRIES	允许core dump会耗费大量的磁盘空间.

2	chown root:root /etc/sysctl.conf
chmod 600 /etc/sysctl.conf	log_martians将进行ip假冒的ip包记录到/var/log/messages
其它核心参数使用CentOS默认值。

四、关闭不必要服务
------------

1	关闭Mail Server
chkconfig postfix off	多数Unix/Linux系统运行Sendmail作为邮件服务器, 而该软件历史上出现过较多安全漏洞,如无必要,禁止该服务



五、SSH安全配置
------------

	设置项	注释:
1	配置空闲登出的超时间隔:
ClientAliveInterval 300
ClientAliveCountMax 0	Vi /etc/ssh/sshd_config

2	禁用 .rhosts 文件
IgnoreRhosts yes	Vi /etc/ssh/sshd_config

3	禁用基于主机的认证
HostbasedAuthentication no	Vi /etc/ssh/sshd_config

4	禁止 root 帐号通过 SSH 登录
PermitRootLogin no	Vi /etc/ssh/sshd_config

5	用警告的 Banner
Banner /etc/issue	Vi /etc/ssh/sshd_config

*7	修改 SSH 端口和限制 IP 绑定：
Port 63456

8	禁用空密码：
PermitEmptyPasswords no	禁止帐号使用空密码进行远程登录SSH
9	记录日志：
LogLevel  INFO	确保在 sshd_config 中将日志级别 LogLevel 设置为 INFO 或者 DEBUG，可通过 logwatch or
logcheck 来阅读日志。

六、启用系统审计服务
------------

审计策略使用STIGs
审计内容包括：系统调用、文件访问、用户登录等。编辑/etc/audit/audit.rules,在文中添加如下内容：
---------------------------audit.rules-------------------------------------------
## This file contains the auditctl rules that are loaded
## whenever the audit daemon is started via the initscripts.
## The rules are simply the parameters that would be passed
## to auditctl.
##
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to panic
-f 2

## Make the loginuid immutable. This prevents tampering with the auid.
--loginuid-immutable

## NOTE:
## 1) if this is being used on a 32 bit machine, comment out the b64 lines
## 2) These rules assume that login under the root account is not allowed.
## 3) It is also assumed that 1000 represents the first usable user account. To
##    be sure, look at UID_MIN in /etc/login.defs.
## 4) If these rules generate too much spurious data for your tastes, limit the
## the syscall file rules with a directory, like -F dir=/etc
## 5) You can search for the results on the key fields in the rules
##
##
## (GEN002880: CAT II) The IAO will ensure the auditing software can
## record the following for each audit event:
##- Date and time of the event
##- Userid that initiated the event
##- Type of event
##- Success or failure of the event
##- For I&A events, the origin of the request (e.g., terminal ID)
##- For events that introduce an object into a user’s address space, and
##  for object deletion events, the name of the object, and in MLS
##  systems, the object’s security level.
##
## Things that could affect time
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -F key=time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
# Introduced in 2.6.39, commented out because it can make false positives
#-a always,exit -F arch=b32 -S clock_adjtime -F key=time-change
#-a always,exit -F arch=b64 -S clock_adjtime -F key=time-change
-w /etc/localtime -p wa -k time-change

## Things that affect identity
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Things that could affect system locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -F key=system-locale

## Things that could affect MAC policy
-a always,exit -F dir=/etc/selinux/ -F perm=wa -F key=MAC-policy


## (GEN002900: CAT III) The IAO will ensure audit files are retained at
## least one year; systems containing SAMI will be retained for five years.
##
## Site action - no action in config files

## (GEN002920: CAT III) The IAO will ensure audit files are backed up
## no less than weekly onto a different system than the system being
## audited or backup media.
##
## Can be done with cron script

## (GEN002700: CAT I) (Previously – G095) The SA will ensure audit data
## files have permissions of 640, or more restrictive.
##
## Done automatically by auditd

## (GEN002720-GEN002840: CAT II) (Previously – G100-G106) The SA will
## configure the auditing system to audit the following events for all
## users and root:
##
## - Logon (unsuccessful and successful) and logout (successful)
##
## Handled by pam, sshd, login, and gdm
## Might also want to watch these files if needing extra information
#-w /var/log/tallylog -p wa -k logins
#-w /var/run/faillock/ -p wa -k logins
#-w /var/log/lastlog -p wa -k logins


##- Process and session initiation (unsuccessful and successful)
##
## The session initiation is audited by pam without any rules needed.
## Might also want to watch this file if needing extra information
#-w /var/run/utmp -p wa -k session
#-w /var/log/btmp -p wa -k session
#-w /var/log/wtmp -p wa -k session

##- Discretionary access control permission modification (unsuccessful
## and successful use of chown/chmod)
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -F key=perm_mod

##- Unauthorized access attempts to files (unsuccessful)
-a always,exit -F arch=b32 -S open,creat,truncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open,creat,truncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access

##- Use of privileged commands (unsuccessful and successful)
## use find /bin -type f -perm -04000 2>/dev/null and put all those files in a rule like this
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged

##- Use of print command (unsuccessful and successful)

##- Export to media (successful)
## You have to mount media before using it. You must disable all automounting
## so that its done manually in order to get the correct user requesting the
## export
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export

##- System startup and shutdown (unsuccessful and successful)

##- Files and programs deleted by the user (successful and unsuccessful)
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -F key=delete

##- All system administration actions
##- All security personnel actions
##
## Look for pam_tty_audit and add it to your login entry point's pam configs.
## If that is not found, use sudo which should be patched to record its
## commands to the audit system. Do not allow unrestricted root shells or
## sudo cannot record the action.
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

## (GEN002860: CAT II) (Previously – G674) The SA and/or IAO will
##ensure old audit logs are closed and new audit logs are started daily.
##
## Site action. Can be assisted by a cron job

## Not specifically required by the STIG; but common sense items
## Optional - could indicate someone trying to do something bad or
## just debugging
#-a always,exit -F arch=b32 -S ptrace -F key=tracing
#-a always,exit -F arch=b64 -S ptrace -F key=tracing
#-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -F key=code-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -F key=code-injection
#-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -F key=data-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -F key=data-injection
#-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -F key=register-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -F key=register-injection

## Optional - might want to watch module insertion
#-w /sbin/insmod -p x -k modules
#-w /sbin/rmmod -p x -k modules
#-w /sbin/modprobe -p x -k modules
#-a always,exit -F arch=b32 -S init_module,finit_module -F key=module-load
#-a always,exit -F arch=b64 -S init_module,finit_module -F key=module-load
#-a always,exit -F arch=b32 -S delete_module -F key=module-unload
#-a always,exit -F arch=b64 -S delete_module -F key=module-unload

## Optional - admin may be abusing power by looking in user's home dir
#-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -F key=power-abuse

## Optional - log container creation
#-a always,exit -F arch=b32 -S clone -F a0&0x7C020000 -F key=container-create
#-a always,exit -F arch=b64 -S clone -F a0&0x7C020000 -F key=container-create

## Optional - watch for containers that may change their configuration
#-a always,exit -F arch=b32 -S unshare,setns -F key=container-config
#-a always,exit -F arch=b64 -S unshare,setns -F key=container-config

## Put your own watches after this point
# -w /your-file -p rwxa -k mykey

## Make the configuration immutable - reboot is required to change audit rules
-e 2

-a exit,always -F arch=b64 -S execve
-a exit,always -F arch=b32 -S execve
---------------------------audit.rules-------------------------------------------
重启audit服务
#service auditd  restart



七、部署完整性检查工具软件
------------

配置说明：
序号	参数	注释
1	/etc/aide.conf	配置文件
2	database	Aide读取文档数据库的位置，默认为/var/lib/aide，默认文件名为aide.db.gz
3	database_out	Aide生成文档数据库的存放位置，默认为/var/lib/aide，默认文件名为aide.db.new.gz
	database_new	在使用aide --compare命令时，需要在aide.conf中事先设置好database_new并指向需要比较的库文件
4	report_url	/var/log/aide，入侵检测报告的存放位置
5	其它参数继续使用默认值即可。
执行aide入侵检测：
1）查看入侵检测报告
#aide --check
报告的详细程度可以通过-V选项来调控，级别为0-255，-V0 最简略，-V255 最详细。
或
#aide --compare
这个命令要求在配置文件中已经同时指定好了新、旧两个库文件。
2）保存入侵检测报告（将检查结果保存到其他文件）
aide --check --report=file：/tmp/aide-report-20120426.txt
3）定期执行入侵检测，并存储报告日志
# crontab -e
45 23 * * * aide -C >> /var/log/aide/'date +%Y%m%d'_aide.log
记录aide可执行文件的md5 checksum：
#md5sum /usr/sbin/aide
需要监控目录清单：
IP	Direcorty


八、开启防火墙策略
------------

防火墙入站出站白名单，端口清单见附件ip_service_detail.xlsx

九、安全启动
------------

	设置项	注释:
1	Grub加密
2	磁盘加密	 LUKS全盘加密


十、日志服务器
------------

1	使用日志服务器：
#vi /etc/rsyslog.conf 照以下样式修改
*.info;mail.none;authpriv.none;cron.none    @192.168.10.199
	这里只是作为参考.

目前策略:
大小超过1G压缩
每天归档 *.gz 的压缩包到 archived目录下，也就是说当前目录只保留当天的日志
保留一个月的备份

十一、备份
------------

机器名称		IP 			备份方式
签名机					硬盘拷贝快照










