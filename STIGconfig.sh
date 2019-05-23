#!/bin/bash

# Author:		xrpx
# Description:		Bash script to implement DISA STIG controls on Redhat-based Linux systems
# Last Modified:	August 18, 2014

################### First Time Run ############################
#echo 'Only intended for the first time run. A reboot is required after execution.'
#echo 'This part resets network configuration rules'
#sed -i 's/HOSTNAME/#HOSTNAME/' /etc/sysconfig/network
#sed -i 's/HWADDR/\#HWADDR/' /etc/sysconfig/network-scripts/ifcfg-eth0
#echo > /etc/udev/rules.d/70-persistent-net.rules
#service network restart

################### One time after installation ##############

# Initiate AIDE
#if [ ! -f /var/lib/aide/aide.db.new.gz ]; then
#        aide --init --config /etc/aide.conf
#        wait $!
#fi

# Initiate PostgreSQL
#/etc/init.d/postgresql initdb
#wait $!

################### Configuration ##############################

## Sync to HWCLOCK - Goes in ntpdate in RHEL6
sed -i 's/\(SYNC_HWCLOCK\)=\(no\)/\1=yes/g' /etc/sysconfig/ntpd
## Keep history worth a month
sed -i 's/\(HISTORY\)=\([0-9]\{1,2\}\)/\1=31/g' /etc/sysconfig/sysstat
# Language Info and Default Timezone
localedef -c -f UTF-8 -i en_US en_US.utf8
ln -sf /usr/share/zoneinfo/EST5EDT /etc/localtime

################## Tomcat Hardening ############################
# Tomcat hardening
# https://www.owasp.org/index.php/Securing_tomcat
# and its discussion page
# http://www.mulesoft.com/tomcat-security

## Are the permissions okay?
chmod 755 /etc/init.d/tomcat
find /opt/tomcat/conf -xtype f -exec chmod 400 {} \;
find /var/log/tomcat -xtype f -exec chmod 300 {} \;
chown -R 91:91 /var/log/tomcat
chown -R 91:91 /opt/tomcat
chown -R 91:91 /opt/tomcat-mod-0.XX
# Rest from the article will probably be faster if done manually for now

################### Server Hardening ###########################

## Restrict SU access to members of group wheel in sudoers and PAM
sed -i 's/^#\([ \t]\+\)\(%wheel\)\([ \t]\+\)\(ALL=(ALL)\)\([ \t]\+\)\(ALL\)/\2\3\4\5\6/g' /etc/sudoers
sed -i 's/#\(auth\)\([ \t]\+\)\(required\)\([ \t]\+\)\(pam_wheel.so\)\([ \t]\+\)\(use_uid\)/\1\2\3\4\5\6\7/g' /etc/pam.d/su
## Restrict permissions
mkdir /root/.ssh # Overkill?
chmod 700 /root/.ssh
[ -d /usr/share/info ] && find /usr/share/info -xtype f -exec chmod 644 {} \;
[ -d /usr/share/infopage ] && find /usr/share/infopage -xtype f -exec chmod 644 {} \;

echo '==================================================='
echo 'Adding MOTD to display banner after login'
echo '==================================================='
cat <<EOF > /etc/motd
----------------------- NOTICE -----------------------------
If you need to review / change Network settings, please type
system-config-network-tui
EOF

############## CLIP STIG-FIXES ##################


###############################################################################
####################    CATEGORY I    #########################################
###############################################################################

## CAT I from here on except this one to relate to MOTD
## (GEN000400: CAT II) (Previously â G010) The SA will ensure a logon-warning banner is
## displayed on all devices and sessions at the initial logon.
echo '==================================================='
echo ' Patching GEN000400: Providing logon-warning banner'
echo '==================================================='
cat <<EOF > /etc/issue-static
********************************************************************************

THIS IS A PRIVATE COMPUTER SYSTEM. THIS COMPUTER
SYSTEM, INCLUDING ALL RELATED EQUIPMENT, NETWORKS, AND
NETWORK DEVICES (SPECIFICALLY INCLUDING INTERNET ACCESS), ARE
PROVIDED ONLY FOR AUTHORIZED USE ONLY. COMPUTER
SYSTEMS MAY BE MONITORED FOR ALL LAWFUL PURPOSES, INCLUDING TO
ENSURE THEIR USE IS AUTHORIZED, FOR MANAGEMENT OF THE SYSTEM, TO
FACILITATE PROTECTION AGAINST UNAUTHORIZED ACCESS, AND TO
VERIFY SECURITY PROCEDURES, SURVIVABILITY, AND OPERATIONAL
SECURITY. MONITORING INCLUDES ACTIVE ATTACKS BY AUTHORIZED 
ENTITIES TO TEST OR VERIFY THE SECURITY OF THIS SYSTEM. DURING
MONITORING, INFORMATION MAY BE EXAMINED, RECORDED, COPIED, AND
USED FOR AUTHORIZED PURPOSES. ALL INFORMATION, INCLUDING
PERSONAL INFORMATION, PLACED ON OR SENT OVER THIS SYSTEM, MAY
BE MONITORED.
USE OF THIS COMPUTER SYSTEM, AUTHORIZED OR
UNAUTHORIZED, CONSTITUTES CONSENT TO MONITORING OF THIS
SYSTEM. UNAUTHORIZED USE MAY SUBJECT YOU TO CRIMINAL
PROSECUTION. EVIDENCE OF UNAUTHORIZED USE COLLECTED
DURING MONITORING MAY BE USED FOR ADMINISTRATIVE,
CRIMINAL, OR OTHER ADVERSE ACTION. USE OF THIS SYSTEM
CONSTITUTES CONSENT TO MONITORING FOR THESE PURPOSES.

********************************************************************************

********************************************************************************
       
EOF
# Put HEREDOC in single quotes. Otherwise, script below gets executed
cat <<'EOE' > /etc/issue-dynamic

echo -e "\nHOSTNAME: `hostname`\n\nNetwork Connectivity:\n"

IFACE=`/sbin/ifconfig | grep "Link encap" | grep -v "lo" | awk '{print $1}'`

for i in $IFACE
  do
    IPADDR=`/sbin/ifconfig $i | grep "inet addr" | awk '{ print $2 }' | awk -F: '{ print $2 }'`
    MAC=`/sbin/ifconfig $i | grep "Link encap" | grep -v "lo" | awk '{print $5}'`
    echo -e "Interface $i\t IP Address: $IPADDR\t MAC: $MAC\n"
  done

echo "*******************************************************************************"

EOE
# Modify permissions for execution for dynamic file
chmod 755 /etc/issue-dynamic

cat <<'EOD' > /etc/rc.local
#!/bin/sh
#
# This script will be executed *after* all the other init scripts.
# You can put your own initialization stuff in here if you don't
# want to do the full Sys V style init stuff.

touch /var/lock/subsys/local

# Update /etc/issue
cp /etc/issue-static /etc/issue
/etc/issue-dynamic >> /etc/issue
echo "" >> /etc/issue

EOD

# Change banner for SSH logins so that it matches the above
sed -i "/^#Banner/ c\Banner /etc/issue" /etc/ssh/sshd_config
sed -i "/^Banner/ c\Banner /etc/issue" /etc/ssh/sshd_config

	
## (GEN000560: CAT I) (Previously â G018) The SA will ensure each account in
## the /etc/passwd file has a password assigned or is disabled in the
## password, shadow, or equivalent, file by disabling the password and/or by
## assigning a false shell in the password file.
echo '==================================================='
echo 'Patching GEN000560: Disable accounts with no'
echo '                    password'
echo '==================================================='
for USERINFO in `cat /etc/shadow`; do
        if [ -z "`echo $USERINFO | cut -d: -f2`" ]
        then
                /usr/sbin/usermod -L -s /sbin/nologin `echo $USERINFO | cut -d: -f1`
        fi
done;

## (GEN001100: CAT I) (Previously – G499) The IAO will require strong I&A, with encryption
## for password and data, for all remote accesses (access from other than the system console)
## by the root account.
## This is subsided by GEN001120. If ssh login to root is not allowed, there is no encryption required.


## (GEN001400: CAT I) (Previously â G047) The SA will ensure the owner of the
## /etc/passwd and /etc/shadow files (or equivalent) is root.
echo '==================================================='
echo 'Patching GEN001400: Set owner of /etc/passwd and'
echo '                    /etc/shadow'
echo '==================================================='
chown root /etc/passwd
chown root /etc/shadow

## GEN002040 - N/A - No rhosts files in RHEL6

## (GEN002160: CAT I) (Previously â G072) The SA will ensure no shell has the
## suid bit set.
echo '==================================================='
echo 'Patching GEN002160: No shells have suid bit set'
echo '==================================================='
for SHELL in `cat /etc/shells`; do
        chmod u-s $SHELL
done

## (GEN002700: CAT I) (Previously â G095) The SA will ensure audit data files
## have permissions of 640, or more restrictive.
echo '==================================================='
echo 'Patching GEN002700: Set audit file permissions'
echo '==================================================='
chmod 640 /var/log/audit/*
chmod 640 /etc/audit/*

## (GEN003820: CAT I) (Previously – V042) The SA will ensure remote login and remote shell are not enabled. - Not Applicable

## GEN004580 - N/A - No .forward files in RHEL6

## (GEN004640: CAT I) (Previously â V126) The SA will ensure the decode entry
## is disabled (deleted or commented out) from the alias file.
echo '==================================================='
echo 'Patching GEN004640: Disable decode in alias file'
echo '==================================================='
sed --in-place s/^decode\:/\#decode\:/ /etc/aliases
/usr/bin/newaliases

## GEN005000 - N/A - already implemented in GEN000560

## (GEN005080: CAT I) (Previously – G149) The SA will ensure the secure mode option is used 
## if TFTP is implemented on a system that supports it.
## This is covered in GEN003800

## (GEN005100: CAT I) (Previously – G150) The SA will ensure tftpd does not have the suid or
## sgid bit set.
chmod u-s /usr/sbin/in.tftpd
chmod g-s /usr/sbin/in.tftpd

## GEN005140 - Document TFTP uses

## (GEN005500: CAT I) (Previously â G701) The IAO and SA will ensure SSH
## Protocol version 1 is not used, nor will Protocol version 1 compatibility
## mode be used. Also implied GEN005520
echo '==================================================='
echo 'Patching GEN005500: Disallow SSH Protocol version 1'
echo '==================================================='
if [ `grep -c "^Protocol" /etc/ssh/sshd_config` -gt 0 ]
then
        sed -i "/^Protocol/ c\Protocol 2" /etc/ssh/sshd_config
else
        echo "Protocol 2" >> /etc/ssh/sshd_config
fi
echo 'Ciphers aes256-cbc,aes192-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,3des-cbc' >> /etc/ssh/ssh_config

## LNX00080 - Boot loader not on boot diskette
## Installed in MBR as defined in kickstart

## LNX00100 - Use GRUB - Using GRUB2 as per kickstart

## LNX00120 - /boot not on removable media - as per kickstart

## LNX00140 - GRUB password MD5 - encrypted with SHA512 in kickstart

## (LNX00320: CAT I) (Previously â L140) The SA will delete accounts that
## provide a special privilege such as shutdown and halt.
echo '==================================================='
echo 'Patching LNX00320: Deleting accounts providing'
echo '                   special privilege.'
echo '==================================================='
/usr/sbin/userdel shutdown
/usr/sbin/userdel halt
/usr/sbin/userdel sync

## LNX00540/LNX00560 - Not Applicable to RHEL6 - secure option is set by default

## (LNX00580: CAT I) (Previously â L222) The SA will disable the
## Ctrl-Alt-Delete sequence unless the system is located in a controlled
## access area accessible only by SAs.
echo '==================================================='
echo ' Patching LNX00580: Disable CTRL-ALT-DELETE'
echo '==================================================='
# 	sed --in-place "s/ca\:\:ctrlaltdel/\#ca\:\:ctrlaltdel/" /et/inittab
#	This does not work in RHEL6 since System V init is replaced by upstart
sed --in-place "s/exec/\#exec/" /etc/init/control-alt-delete.conf 
echo "exec echo \"Control-Alt-Delete restart sequence disabled\"" >> /etc/init/control-alt-delete.conf






###############################################################################
####################    CATEGORY II    ########################################
###############################################################################



## (GEN000020: CAT II) (Previously â G001) The IAO and SA will ensure, if
## configurable, the UNIX host is configured to require a password for access
## to single-user and maintenance modes.
echo '==================================================='
echo ' Patching GEN000020: Configuring Password for'
echo '                     single-user and maintenance'
echo '                     modes.'
echo '==================================================='
# 	echo "" >> /etc/inittab
# 	echo "#Require password in single-user mode" >> /etc/inittab
# 	echo "~~:S:wait:/sbin/sulogin" >> /etc/inittab
#	N/A since RHEL6 has upstart
sed --in-place "s/SINGLE/\#SINGLE/" /etc/sysconfig/init
echo "SINGLE=/sbin/sulogin" >> /etc/sysconfig/init

# (GEN000040: CAT II) (Previously – G002) The SA will ensure a UNIX host that cannot be
# configured to require a password when booted to single-user mode is justified and
# documented with the IAO.
# GEN000060 - such host is located in controlled access area
# N/A - GEN000020 has been satisfied
# GEN000080 - All UNIX system equipment is located in controlled access area
# Site responsibility - physical security

# GEN000100 - RHEL6 is a supported release
# GEN000120 - Managed with Red Hat Network - patches are regularly applied

# Following are responsiblity of client
# GEN000140 - Baseline of system hashes
# GEN000160 - Backup baselines
# GEN000180 - Create new baseline after any changes to SGID/SUID files are made
# GEN000200 - Create new baseline after any changes to system libraries/binaries are made
# GEN000220 - Weekly check status against baseline

# GEN000240 - Use trusted time servers - No data available

# GEN000260/GEN000280 - No shared accounts; If required; individual account and then SU to shared

# GEN000400 Check at the start of Category I

# GEN000440 RHEL6 already logs this at INFO level with facility authpriv and not auth
# Also, this is covered under GEN3660

## (GEN000460: CAT II) (Previously â G013) The SA will ensure, after three consecutive
## failed logon attempts for an account, the account is locked for 15 minutes or until
## the SA unlocks the account.
## RHEL6 has pam_tally2.so and not pam_tally3.so
echo '==================================================='
echo ' Patching GEN000460: Disable after 3 consecutive'
echo '                     failed attempts per account'
echo '==================================================='
cat <<EOF > /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
#5 login attempts within 30 seconds.  Locked out for 60 seconds if fail
auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=900
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass audit
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
 	
account     required      pam_unix.so
account     required      pam_tally2.so audit
# pam_localuser is to allow access to local users only; no LDAP
#account	    sufficient	  pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
password    required      pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=10
password    required      pam_deny.so
 	
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOF
 	
# auth config overwrites these changes, make it non executable
chmod ugo-x /usr/sbin/authconfig
chmod ugo-x /usr/sbin/authconfig-tui

# GEN000480 Login delay for failed login 4 seconds - N/A - RHEL6 has default value 15 seconds

## (GEN000500: CAT II) (Previously â G605) The SA will configure systems to log
## out interactive processes (i.e., terminal sessions, ssh sessions, etc.,)
## after 15 minutes of inactivity or ensure a password protected screen lock
## mechanism is used and is set to lock the screen after 15 minutes of
## inactivity.
echo '==================================================='
echo 'Patching GEN000500: Set inactive shell timeout'
echo '==================================================='
cat <<EOE > /etc/profile.d/tmout.sh
# Auto logout after inactivity of 15 minutes
TMOUT=900
readonly TMOUT
export TMOUT
EOE


## GEN000520 - Not Applicable - No real time data monitoring in place

## (GEN000540: CAT II) (Previously â G004) The SA will ensure passwords are
## not changed more than once a day.
echo '==================================================='
echo 'Patching GEN000540: Set minimum number of days'
echo '                    between password changes'
echo '==================================================='
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS\t1' /etc/login.defs

# GEN000580 Minimum length 8 characters - N/A
# RHEL6 has PASS_MIN_LEN 8 default set up. Also, PAM overrides this file now.
## (GEN000580: CAT II) (Previously â G019) The IAO will ensure all passwords contain a
## minimum of eight characters.
echo '==================================================='
echo ' Patching GEN000580: Set minimum Password length.'
echo '==================================================='
sed -i '/^PASS_MIN_LEN/ c\PASS_MIN_LEN\t8' /etc/login.defs



# GEN000600 Minimum 2 alphabets and 1 caiptal - GEN000460
# GEN000620 At least 1 numeric character - GEN000460
# GEN000640 At least 1 special character - GEN000460
## Avoid @ or # - Not Possible
# GEN000660 Manual password crack check will prove this
# GEN000680 Linux property as per scripts

# GEN000700 Passwords expire every 90 days - Default in RHEL6
## (GEN000700: CAT II) (Previously â G020) The SA will ensure passwords are
## changed at least every 90 days.
echo '==================================================='
echo 'Patching GEN000700: Set maximum number of days'
echo '                    between password changes'
echo '==================================================='
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS\t90' /etc/login.defs

# GEN000720 - Same as above for root account
# GEN000740 - Same as above for system accounts

## GEN000760 - Lock accounts inactive for more than 30 days
## There is no direct way to accomplish this. 
## We can apply these settings to any users created after this.
## First, no grace period after password expires
sed -i '/^INACTIVE/ c\INACTIVE\=0' /etc/default/useradd
## MAX DAYS and MIN DAYS is set. Let's set WARN
sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE\t14' /etc/login.defs
## For current accounts, CHAGE should do it
for NAME in `cut -d: -f1 /etc/passwd`; do
     if [ $NAME != 'root' ]; then
	chage -I0 -M90 -m7 -W14 $NAME
     fi
done

# GEN000780 - Password crack check

# GEN000800 Don't use last 10 passwords - GEN000460

# GEN000820 - Global files are configured for above - YES
# GEN000840 - Whoever gets root access must be documented
# GEN000860 - Change root password after person with access is reassigned

# (GEN000880: CAT II) (Previously – G021) The SA will ensure only root has a uid of 0.
if [ `cut -d ":" -f 3,3 /etc/passwd | grep '^0' | wc -l` -gt 1 ]
then
	echo "CRITICAL ERROR: MORE THAN ONE ACCOUNT HAS UID 0"
fi

# (GEN000900: CAT IV) (Previously – G022) The SA will ensure root is assigned a home
# directory other than ‘/’ (e.g., /roothome).
## This one is Linux default

## (GEN000920: CAT II) (Previously â G023) The SA will ensure the root account
## home directory (other than â/â) has permissions of 700. Do not change the
## permissions of the â/â directory to anything other than 0755.
echo '==================================================='
echo ' Patching GEN000920: /root is only readable by root'
echo '==================================================='
chmod 700 /root

## GEN000940 - If found, do a manual fix. Too risky to script without knowing the findings.
## GEN000960 - same as above

## (GEN000980: CAT II) (Previously â G026) The SA will ensure root can only log
## on as root from the system console, and then only when necessary to perform
## system maintenance.
echo '==================================================='
echo ' Patching GEN000980: Ensure only one secure TTY.'
echo '==================================================='
echo "console" > /etc/securetty

## GEN001000 - Completed in GEN000980

## (GEN001020: CAT II) The IAO will enforce users requiring root privileges to
## log on to their personal account and invoke the /bin/su - command to switch
## user to root.
echo '==================================================='
echo ' Patching GEN001020: root privilege must be gained'
echo '                     via switch from user account.'
echo '==================================================='
sed -i '/^account.*auth$/ a\account\t\trequired\tpam_access.so' /etc/pam.d/sshd
sed -i '/^account.*auth$/ a\account\t\trequired\tpam_access.so' /etc/pam.d/login
cat <<EOF >> /etc/securityaccess.conf
#only access for root is cron
+:root: cron crond
-:ALL EXCEPT users :ALL
EOF

## GEN001040 / GEN001060 - rsyslog is logging auth.* and authpriv.*

## (GEN001120: CAT II) (Previously â G500) The SA will configure the
## encryption program for direct root access only from the system console.
echo '==================================================='
echo 'Patching GEN001120: Do not allow root remote login'
echo '==================================================='
sed -i "/^#PermitRootLogin/ c\PermitRootLogin no" /etc/ssh/sshd_config
sed -i "/^PermitRootLogin/ c\PermitRootLogin no" /etc/ssh/sshd_config


## GEN001140/GEN001160/GEN001180/GEN001200/GEN001220/GEN001240/GEN001300
## Are easier to mitigate after DISA scripts run
## If we attempt permission change without review, it will break things badly

## (GEN001260: CAT II) (Previously â G037) The SA will ensure all system log
## files have permissions of 640, or more restrictive.
echo '==================================================='
echo ' Patching GEN001260: Setting permissions of system'
echo '                     log files.'
echo '==================================================='
find /var/log/ -type f -exec chmod 640 '{}' \;
chown -R tomcat:tomcat /var/log/tomcat
sed -i "s/chmod 0664/chmod 0640/" /etc/rc.d/rc.sysinit


## GEN001320/GEN001340/GEN001360 - NIS/NIS+/YP - Not Applicable

# GEN001380/GEN001400/GEN001420 - Let's leave them at default RHEL6 - 644/000 - root:root

## (GEN001480: CAT II) (Previously – G053) The SA will ensure user home directories have
## initial permissions of 700, and never more permissive than 750.
## GEN001500 - Home directory is owned by user
## GEN001520 - Home directory is owned by user's primary group
## GEN001540 - Home directory files owned by user
echo '==================================================='
echo 'Patching GEN001480: Fixing home directories'
echo '			  Ownership and Permissions'
echo '==================================================='
USER_NAME=`grep "/home/" /etc/passwd | cut -d: -f1`

for NAME in ${USER_NAME}
do
    USER_HD=`grep ${NAME} /etc/passwd | cut -d: -f6`
    USER_ID=`grep ${NAME} /etc/passwd | cut -d: -f3`
    GROUP_ID=`grep ${NAME} /etc/passwd | cut -d: -f4`
    chown -R ${USER_ID} ${USER_HD}
    chgrp ${GROUP_ID} ${USER_HD}
done
## Inside home directory, group should not be changed for sharing; only owner


## (GEN001560: CAT II) (Previously â G068) The user, application developers,
## and the SA will ensure user files and directories will have an initial
## permission no more permissive than 700, and never more permissive than 750.
echo '==================================================='
echo 'Patching GEN001560: Set home dir permissions'
echo '==================================================='
for BASEDIR  in "/home/* /root"
do
        find $BASEDIR -type f -exec chmod 600 '{}' \;
        find $BASEDIR -type d -exec chmod 700 '{}' \;
done
# Home permissions are set to these by default; wouldnt hurt to re do in case they have been altered

## (GEN001580: CAT II) (Previously â G058) The SA will ensure run control
## scripts have permissions of 755, or more restrictive.
echo '==================================================='
echo 'Patching GEN001580: Set permissions of run control'
echo '                    scripts'
echo '==================================================='
chmod 755 /etc/rc.d/init.d/*

## GEN001600 - PATH in run control scripts - must be done manually - stuff will break

## (GEN001620: CAT II) (Previously â G061) The SA will ensure run control
## scripts files do not have the suid or sgid bit set.
echo '==================================================='
echo 'Patching GEN001620: Remove suid and sgid bit from'
echo '                    run control scripts.'
echo '==================================================='
chmod ug-s /etc/rc.d/init.d/*

## GEN001640 - World wriatble - GEN001580 nullifies this

## (GEN001660: CAT II) (Previously â G611) The SA will ensure the owner of run
## control scripts is root.
echo '==================================================='
echo 'Patching GEN001660: Set owner of run control'
echo '                    scripts'
echo '==================================================='
chown root /etc/rc.d/init.d/*

## (GEN001680: CAT II) (Previously â G612) The SA will ensure the group owner
## of run control scripts is root, sys, bin, other, or the system default.
echo '==================================================='
echo 'Patching GEN001680: Set group owner of run control'
echo '                    scripts'
echo '==================================================='
chgrp root /etc/rc.d/init.d/*

## GEN001700 - Please do this manually

## (GEN001720: CAT II) The SA will ensure global initialization files have
## permissions of 644, or more restrictive.
echo '==================================================='
echo 'Patching GEN001720: Set permissions of global'
echo '                    initialization files'
echo '==================================================='
chmod 644 /etc/{profile,bashrc,environment}

## (GEN001740: CAT II) The SA will ensure the owner of global initialization
## files is root.
echo '==================================================='
echo 'Patching GEN001740: Set owner of global'
echo '                    initialization files'
echo '==================================================='
chown root /etc/{profile,bashrc,environment}

## (GEN001760: CAT II) The SA will ensure the group owner of global
## initialization files is root, sys, bin, other, or the system default.
echo '==================================================='
echo 'Patching GEN001760: Set group owner of global'
echo '                    initialization files'
echo '==================================================='
chgrp root /etc/{profile,bashrc,environment}

## (GEN001800: CAT II) (Previously â G038) The SA will ensure all
## default/skeleton dot files have permissions of 644, or more restrictive.
echo '==================================================='
echo 'Patching GEN001800: Set permissions of default /'
echo '                    skeleton files'
echo '==================================================='
find /etc/skel -type f -exec chmod 644 '{}' \;

## (GEN001820: CAT II) The SA will ensure the owner of all default/skeleton
## dot files is root or bin.
echo '==================================================='
echo 'Patching GEN001820: Set owner of default/skel files'
echo '==================================================='
find /etc/skel -type f -exec chown root '{}' \;

## GEN001840 - Must be done manually

## GEN001860/GEN001880 - GEN001540 makes user the owner for all and corrects permissions
## GEN001900/GEN001920/GEN001940/GEN001960 - Manual review, if found
## GEN001980/GEN002000/GEN002020/GEN002040/GEN002060/GEN002080/GEN002100 - NOT APPLICABLE

## (GEN002120: CAT II) (Previously G069) The SA will ensure the /etc/shells
## (or equivalent) file exits.
## GEN002140 - /sbin/nologin is valid for /etc/passwd but not to be listed in /etc/shells
echo '==================================================='
echo 'Patching GEN002120: Set /etc/shells'
echo '==================================================='
cat <<EOF > /etc/shells
/bin/sh
/bin/bash
/bin/tcsh
/bin/csh
EOF

## (GEN002180: CAT II) (Previously â G073) The SA will ensure no shell has the
## sgid bit set.
echo '==================================================='
echo 'Patching GEN002180: No shells have sgid bit set'
echo '==================================================='
for SHELL in `cat /etc/shells`; do
        chmod g-s $SHELL
done

## (GEN002200: CAT II) (Previously â G074) The SA will ensure the owner of all
## shells is root or bin.
echo '==================================================='
echo 'Patching GEN002200: Set shell owners to root'
echo '==================================================='
for SHELL in `cat /etc/shells`; do
        chown root $SHELL
done

## (GEN002220: CAT II) (Previously â G075) The SA will ensure all shells
## (excluding /dev/null and sdshell) have permissions of 755, or more
## restrictive.
echo '==================================================='
echo 'Patching GEN002220: Set shell permissions'
echo '==================================================='
for SHELL in `cat /etc/shells`; do
        chmod 755 $SHELL
done

## GEN002240/GEN002260/GEN002280 - No changes in vendor configuration
## GEN002300 - Backup devices - Site responsibility

## (GEN002320: CAT II) (Previously â G501) The SA will ensure the audio devices
## have permissions of 644, or more restrictive.
## RHEL6 removed 50-default.perms file due to security risk
## Only console permissions are those listed in /etc/security/console.perms and sound is 
## not included in it
echo '==================================================='
echo ' Patching GEN002320: Setting permissions on audio'
echo '                     devices.'
echo '==================================================='
# prevent pam from changing the owner when logging in
#sed -i -r "/sound|snd|mixer/ d" /etc/security/console.perms.d/50-default.perms
# have udev set the permissions/owner/group
## GEN002340 - Set group ownership of audio devices
## GEN002360 - Set permissions of audio devices
echo "SUBSYSTEM==\"sound|snd\", OWNER=\"root\", GROUP=\"root\", MODE=\"0644\"" > /etc/udev/rules.d/55-audio-perms.rules

## GEN002380/GEN002400 - No SUID file expected - Manual review

## (GEN002420: CAT II) (Previously â G086) The SA will ensure user filesystems,
## removable media, and remote filesystems will be mounted with the nosuid
## option.
echo '==================================================='
echo 'Patching GEN002420: Mount filesystems with nosuid'
echo '==================================================='
## Kickstart file applies nosuid, nodev, acl and noatime option to all partitions as appropriate
## /sys is not a real partition and hence, options should be applied after install
FSTAB=/etc/fstab
SED=/bin/sed
#nosuid and acl on /sys
if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
        MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nosuid,acl/" ${FSTAB}
fi

## GEN002440/GEN002460 - No SGID file expected - Manual review
## GEN002480/GEN002500/GEN002520/GEN002540 - World writable => /tmp
## /tmp has mount options for nosuid, noexec, noatime and nodev
## Put sticky bit on /tmp and subdirectories; Owned by root
chmod 1777 /tmp
chown root:root /tmp
# Bind /var/tmp to /tmp so that it inherits all the options
mount --bind /tmp /var/tmp
echo "/tmp	/var/tmp	none	bind	0 0" >> /etc/fstab


## (GEN002560: CAT II) (Previously â G089) The SA will ensure the system and
## user umask is 077.
echo '==================================================='
echo ' Patching GEN002560: Set default umask.'
echo '==================================================='
sed -i "/umask/ c\umask 077" /etc/bashrc
sed -i "/umask/ c\umask 077" /etc/csh.cshrc

## GEN002580 - If found, do a manual review

## GEN002600 - Site responsibility

## GEN002620 - Password crack testing

## (GEN002640: CAT II) (Previously â G092) The SA will ensure logon capability
## to default system accounts (e.g., bin, lib, uucp, news, sys, guest, daemon,
## and any default account not normally logged onto) will be disabled by
## making the default shell /bin/false, /usr/bin/false, /sbin/false,
## /sbin/nologin, or /dev/null, and by locking the password.

## For our purposes, it is identical to GEN00560 since none of the accounts but
## root and admin have password assigned but check is a good idea in case 
## newly created accounts such as tomcat are accidently assigned a shell
echo '==================================================='
echo 'Patching GEN002640: Lock default system accounts'
echo '==================================================='
for NAME in `cut -d: -f1 /etc/passwd`; do
     NAMEID=`id -u $NAME`
     if [ $NAMEID -lt 500 -a $NAME != 'root' ]; then
         /usr/sbin/usermod -L -s /sbin/nologin $NAME
     fi
done

## (GEN002660: CAT II) (Previously â G093) The SA will configure and implement
## auditing. Options are -D for flush previous rules, -e is enable but dont lock config changes,
## -b is buffer size and -f number of failures till kernel panick
## GEN002720 - Log (un)successful logins and successful logouts
## GEN002740 - Log (un)successful use of chown / chmod
## GEN002760 - Log unauthorized access to files
## GEN002780 - Log use of privileged commands
## GEN002800 - Log any deletion of files and programs
## GEN002820 - All actions by a sysadmin
## GEN002840 - Log actions by security personnel
echo '==================================================='
echo 'Patching GEN002660: Turn on auditing'
echo '==================================================='
/sbin/chkconfig auditd on
cat <<EOF > /etc/audit/audit.rules
# Flush previous rules
-D
# Enabled but no lock on config
-e 1
# Buffer size
-b 16384
# Fails till kernel panick
-f 2
# Logins and logouts
-w /bin/login -p x
-w /bin/logout -p x
# chown and chmod usage
-a exit,always -F arch=b64 -S chmod -S chown -S fchmod -S fchown -S lchown
# unauthrized access attempts to files
-a exit,always -F arch=b64 -S open -F success=0
-a exit,always -F arch=b64 -F success=0 -S mknod -S pipe -S mkdir -S creat -S truncate -S ftruncate
# Privileged commands
-w /usr/sbin/pwck
-w /bin/chgrp
-w /usr/bin/newgrp
-w /usr/sbin/groupadd
-w /usr/sbin/groupmod
-w /usr/sbin/groupdel
-w /usr/sbin/useradd
-w /usr/sbin/userdel
-w /usr/sbin/usermod
-w /usr/bin/chage
-w /usr/bin/setfacl
-w /usr/bin/chacl
-a exit,always -F arch=b64 -S chroot -S mount -S umount2 -S adjtimex -S kill
# Files and programs deleted
-a exit,always -F arch=b64 -S unlink -S rmdir -S rename -S link -S symlink
# system administration actions
-w /var/log/audit/audit.log
-w /var/log/audit/audit[1-4].log
-w /var/log/messages
-w /var/log/lastlog
-w /var/log/faillog
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa
-w /etc/selinux/config -p wa
-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/group  -p wa
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d -p wa
-w /etc/ssh/sshd_config
-w /etc/pam.d
-w /etc/login.defs
-w /etc/rc.d/init.d
-w /etc/inittab -p wa
-w /var/run/utmp
-w /var/run/wtmp
-a exit,always -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setdomainname -S setrlimit -S settimeofday -S swapon
# Access by security personnel
-a exit,always -F arch=b64 -S init_module -S delete_module -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr
-w /bin/su
EOF
## RHEL6 defaults are great. We will adjust logs as per space available
sed -i "/max_log_file/ c\max_log_file\ \=\ 10" /etc/audit/auditd.conf
sed -i "/max_log_file_action/ c\max_log_file_action\ \=\ SYSLOG" /etc/audit/auditd.conf
## HALT will completely stop the server if partition is full
## Researching on requirement and feasibility of this one
#sed -i 's/SUSPEND/HALT/g' /etc/audit/auditd.conf

## (GEN002680: CAT II) (Previously â G094) The SA will ensure audit data files
## and directories will be readable only by personnel authorized by the IAO.
echo '==================================================='
echo 'Patching GEN002680: Set audit directory permissions'
echo '==================================================='
chmod 700 /var/log/audit

## (GEN002860: CAT II) (Previously â G674) The SA and/or IAO will ensure old
## audit logs are closed and new audit logs are started daily.
echo '==================================================='
echo 'Patching GEN002860: Rotate audit logs daily'
echo '==================================================='
cat <<EOF > /etc/logrotate.d/audit
/var/log/audit/audit.log {
        daily
        notifempty
        missingok
	rotate 365
	size 10M
        postrotate
        /sbin/service auditd restart 2> /dev/null > /dev/null || true
        endscript
}
EOF


## CRON and AT permissions
## GEN002960 - use cron.allow and cron.deny
## GEN002980 - cron.allow permissions 600 or less
## GEN003000 - do not execute world writable scripts - MANUAL
## GEN003020 - do not execute scripts in world writable directories - MANUAL
## GEN003040 - owner of crontabs is root
## GEN003060 - cron access restricted to root
## GEN003080 - crontab permissions
## GEN003100 - crontab directory permissions
## GEN003120 - owner of cron directories
## GEN003140 - group of cron directories
## GEN003160 - cron logging - RHEL6 default
## GEN003180 - cron log permissions
## GEN003200 - cron.deny permissions
## GEN003220 - crontab umask 077 or higher - MANUAL
## GEN003240 - cron.allow owner and group
## GEN003260 - cron.deny owner and group
## GEN003280 - use at.allow and at.deny
## GEN003300 - at.deny everyone but root
## GEN003320 - at.allow only root
## GEN003340 - at permissions
## GEN003360/80 - MANUAL - similar to 3000/20
## GEN003400 - at directories permissions
## GEN003420 - at directories Owner
## GEN003460 - at.allow Owner
## GEN003480 - at.deny Owner

echo '==================================================='
echo 'Patching CRON and AT permissions'
echo '==================================================='
touch /etc/cron.allow /etc/cron.deny
chmod 600 /etc/cron.allow /etc/cron.deny
chmod 600 /etc/at.allow /etc/at.deny
chown root:root /etc/cron.allow /etc/cron.deny
chown root:root /etc/at.allow /etc/at.deny

chown -R root:root /etc/cron.hourly
chown -R root:root /etc/cron.daily
chown -R root:root /etc/cron.weekly
chown -R root:root /etc/cron.monthly
chown -R root:root /etc/cron.d
chown -R root:root /var/spool/cron
chown -R root:root /var/spool/at/spool
# Restrict crontab to root only (When listed in both allow and deny; allow takes precedence)
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
# On a second note, this might be changed to default deny in future versions as Solaris
# Better to explicitely DENY all other accounts
#echo "ALL" > /etc/cron.deny
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

chmod -R 700 /etc/cron.daily
chmod -R 700 /etc/cron.hourly
chmod -R 700 /etc/cron.weekly
chmod -R 700 /etc/cron.monthly
chmod 600 /etc/crontab
chmod -R 600 /etc/cron.d
chmod -R 600 /var/spool/cron
chmod 755 /etc/cron.hourly
chmod 755 /etc/cron.daily
chmod 755 /etc/cron.weekly
chmod 755 /etc/cron.monthly
chmod 755 /etc/cron.d
chmod 755 /var/spool/cron
chmod 600 /var/log/cron
chmod 755 /var/spool/at/spool

## (GEN003540: CAT II) The SA will ensure the executable stack is disabled.
echo "Check hardware support for PAE - NX by CPU flags"
## egrep "^flags" /proc/cpuinfo
echo "# Exec shield to apply No execute bit" >> /etc/sysctl.conf
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf

## (GEN003560: CAT II) The SA will ensure NFS client requests are restricted.
## Restrict to client request coming from only restricted ports
## echo 'GEN003560 will break NFS requests from kiosk clients'

## (GEN003580: CAT II) The SA will ensure more random TCP sequence numbers are used.
echo "Linux has ISN generators for satisfactory level of randomization"

## (GEN003600: CAT II) The SA will ensure network parameters are securely set.
echo '==================================================='
echo ' Patching GEN003600: Set network parameters'
echo '==================================================='
sed -i "/net\.ipv4\.conf\.default\.rp_filter/ c\net.ipv4.conf.default.rp_filter = 1" /etc/sysctl.conf
sed -i "/net\.ipv4\.conf\.default\.accept_source_route/ c\net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf
cat <<-EOF >> /etc/sysctl.conf
        net.ipv4.tcp_max_syn_backlog = 1280
        net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

## (GEN003620: CAT III) The SA will configure separate filesystem partitions for /home,
## /export/home, and /var unless justified and documented with the IAO.
## Satisfied in kickstart file; we do not need /export

## (GEN003640: CAT II) (Previously – G690) The SA will ensure logging is implemented for the root filesystem.
## Implemented multiple times - N/A

## (GEN003660: CAT II) The SA will ensure the authentication notice and
## informational data is logged.
## RHEL6 tends to log most of this facility under authpriv but let's put this in 
## just in case there is any logging occuring for auth
echo '==================================================='
echo 'Patching GEN003660: Log autentication notice and'
echo '                    informational data'
echo '==================================================='
echo "auth.*					/var/log/messages" >> /etc/rsyslog.conf

## (GEN003700: CAT II) The SA will ensure inetd (xinetd for Linux) is disabled
## if all inetd/xinetd based services are disabled.
echo '==================================================='
echo 'Patching GEN003700: Turn off unneeded services'
echo '==================================================='
# Not installed
# /sbin/chkconfig bluetooth off
# /sbin/chkconfig irda off
# /sbin/chkconfig lm_sensors off
# Using portreserve instead
# /sbin/chkconfig portmap off
# Not installed
# /sbin/chkconfig rawdevices off
# Turned off in kickstart
/sbin/chkconfig rpcgssd off
/sbin/chkconfig rpcidmapd off
/sbin/chkconfig rpcsvcgssd off
# Not installed
# /sbin/chkconfig sendmail off
# Can't do !! TFTP
# /sbin/chkconfig xinetd off

## GEN003720 - Covered after this

## (GEN003740: CAT II) (Previously â G108) The SA will ensure the inetd.conf
## (xinetd.conf for Linux) file has permissions of 440, or more restrictive.
## The Linux xinetd.d directory will have permissions of 755, or more
## restrictive. This is to include any directories defined in the includedir
## parameter.
## We don't regularly change xinetd.conf so 400 is fine
## Everything under directory can go as 600
## Also check Owner since we are using these services
echo '==================================================='
echo ' Patching GEN003740: Set permissions for xinetd'
echo '                     configuration files.'
echo '==================================================='
chmod 755 /etc/xinetd.d
chmod 600 /etc/xinetd.d/*
chmod 400 /etc/xinetd.conf
chown root:root /etc/xinetd.conf
chown -R root:root /etc/xinetd.d

## (GEN003760: CAT II) (Previously â G109) The SA will ensure the owner of the
## services file is root or bin.
## GEN003780 - Permissions 644 or more restrictive
echo '==================================================='
echo 'Patching GEN003760/GEN003780: Owner / permissions of services file'
echo '==================================================='
chown root /etc/services
chmod 644 /etc/services

## GEN003800 - Logging is enabled for xinetd
## xinetd.conf logs to syslog on loglevel INFO; Let's confirm TFTP
## introduce tabs with ctrl+v and [tab]
## --secure option is for GEN005080
sed -i "/server_args/ c\	server_args		= --secure -vvv /tftpboot" /etc/xinetd.d/tftp

## GEN003880/3900/3920/3940 - NOT APPLICABLE - CUPS listens on localhost only

## (GEN003960: CAT II) (Previously â G631) The SA will ensure the owner of
## the traceroute command is root.
## GEN003980 - Group owner is root
## GEN004000 - 700 for traceroute to avoid network discovery
echo '==================================================='
echo 'Patching GEN003960/GEN004000: Owner and permissions for traceroute'
echo '==================================================='
chown root:root /bin/traceroute
chmod 700 /bin/traceroute

## GEN004020/4040/4060/4080/4100/4120/4140/4160/4180/4200/4240/4260/4280/4300/4320/4340 => Client Web Browser
rpm -qa | grep -ir 'firefox\|w3m\|lynx\|nspr'
if [ $? -ne 1 ]; then
        echo "Web Browser Found. Does not satisfy GEN004020-GEN004340 requirements."
fi

## (GEN004360: CAT II) (Previously â G127) The SA will ensure the aliases file
## is owned by root.	
## GEN004380 - Permissions for etc aliases
echo '==================================================='
echo 'Patching GEN004360: Owner and permissions of aliases file'
echo '==================================================='
chown root:root /etc/aliases
chmod 644 /etc/aliases

## GEN004360/4380/4400/4420/4440/4460/4480/4500/4520/4540/4560/4600/4620/4640/4680/4700 - Sendmail or another SMTP server
netstat -antupl | grep 25 | grep -v '127\.0\.0\.1\|\:\:1'
if [ $? -ne 1 ]; then
	echo "SMTP server running more exposed than just localhost. Please process GEN004360-GEN004700"

## (GEN004480: CAT II) (Previously â G135) The SA will ensure the owner of the
## critical sendmail log file is root.
## GEN004500 - Permissions for maillog 640 or more restrictive
echo '==================================================='
echo 'Patching GEN004480: Set owner of mail log file'
echo '==================================================='
chown root:root /var/log/maillog
chmod 600 /var/log/maillog




######## SENDMAIL Specific STIGs do not apply since we are using postfix
######## and its listening only on 127.0.0.1
######## GEN004560 - Postfix does not display version by default which we have
## (GEN004540: CAT II) The SA will ensure the help sendmail command is
## disabled.
## We do NOT use sendmail
#echo '==================================================='
#echo ' Patching GEN004540: Disable sendmail help.'
#echo '==================================================='
#mv /etc/mail/helpfile /etc/mail/helpfile.bak
#echo "" > /etc/mail/helpfile
#sed -i '/HelpFile/s/^/#/' /etc/mail/sendmail.cf

## (GEN004560: CAT II) (Previously â G646) To help mask the e-mail version,
## the SA will use the following in place of the original sendmail greeting
## message:
##   O SmtpGreetingMessage= Mail Server Ready ; $b
 	
#echo '==================================================='
#echo 'Patching GEN004560: Set sendmail greeting message'
#echo '==================================================='
#sed -i '/SmtpGreetingMessage/ c\
#O SmtpGreetingMessage= Mail Server Ready ; $b' /etc/mail/sendmail.cf

######## FTP/TELNET/FSP server is installed. So, following are not applicable
## GEN004720/4740/4760/4780/4800/4820/4840/4860

## (GEN004880: CAT II) (Previously â G140) The SA will ensure the ftpusers
## file exists.
## GEN004900 - Manage ftpusers file  
## GEN004920 - Owner of ftpusers file
## GEN004940 - Permissions of ftpusers file
## And, GEN004960/4980/5020/5040/5060

## (GEN005120: CAT II) (Previously – G151) The SA will ensure implementations of TFTP
## will be configured to vendor specifications and will include the following:
## A TFTP user will be created.
## The default shell will be set /bin/false, or equivalent.
## A home directory owned by the TFTP user will be created.
grep tftp /etc/passwd
if [ $? == 1 ]; then
	groupadd -g 101 tftp
	useradd -c "TFTP Server User" -u 101 -g 101 -s /sbin/nologin tftp
fi

## GEN005160/5180/5200/5220/5240/5260 - Not Applicable as we do not use X Server

## GEN005280 - RHEL6 does not do UUCP

######## We do NOT need SNMP or TRAP installed. If its installed, get rid of it
rpm -q net-snmp-libs
# $? = 1 is not installed
if [ $? -ne 1 ]; then
        yum -y remove net-snmp-libs
fi
## Now that we do not have it, these STIGs are N/A
## GEN005300/5320/5340/5360/5380
	
## SYSLOG configurations - This will probably fail because RHEL6 uses rsyslog
## Appying all configurations to rsyslog instead
## GEN005400 - syslog.conf permissions and Owner
## GEN005420 - syslog.conf group Owner
chown root:root /etc/rsyslog.conf
chmod 640 /etc/rsyslog.conf

## GEN005440/5460/5480 - If we end up deploying remote logging using rsyslog, server config and kiosk
## client details must be documented

## (GEN005540: CAT II) The SA will ensure SSH is configured to work with TCP_WRAPPERS
## except in cases where the encryption utility can be configured for IP filtering and still display
## banners before granting access.
## Manual review based on site IP addresses; configure accordingly

## (GEN005560: CAT II) (Previously – G661) The SA will ensure systems not running routing
## have a default gateway defined.
if [ `netstat -r | grep -c "^default"` -eq 0 ]; then
do
	echo "Configure Default Gateway"
done
## GEN005580 - Manual Review

## (GEN005600: CAT II) The SA will ensure IP forwarding is disabled if the
## system is not dedicated as a router.
echo '==================================================='
echo 'Patching GEN005600: Disable IP forwarding'
echo '==================================================='
sed -i "/net\.ipv4\.ip_forward/ c\net.ipv4.ip_forward = 0" /etc/sysctl.conf

## GEN005620/5640/5660/5680/5700 - Not Applicable

## (GEN005720: CAT II) (Previously – G177) The SA will ensure, if NFS is running, NFS port
## monitoring will be enabled.
## GEN005720 - NFS Port Monitoring: “Linux does not use nfs_portmon. 
## By default, it exports with the -secure option which is the same as nfs_portmon

## GEN005740
echo '==================================================='
echo 'Patching GEN005740: Set owner of export config file'
echo '==================================================='
chown root:root /etc/exports
## GEN005760 - Permissions for export file
chmod 644 /etc/exports
## For GEN005780 - We export it as read only - ro
## If not mentioned, RHEL6 default is read only

## GEN005800 - Exported file system is owned by root; Exports are /tftpboot/ubuntu1104
chown -R root:root /tftpboot

## GEN005820/5860/5880/5900 - NOT POSSIBLE
## We MUST mount NFS FS as root
## GEN005840 - Manual Review
## Pending - till GEN005900

## GEN006000/6020 - IM Apps - Not Applicable
## GEN006040 - P2P - Not Applicable
## GEN006060/6080/6100 - SMB - Not Applicable

###### samba is not installed. Following go as N/A
## GEN006100 - Owner of smb.conf file
## GEN006120 - Group membership of smb.conf file
## GEN006140 - Permissions of smb.conf file
## GEN006160 - Owner of smbpasswd
## GEN006180 - Group owner of smbpasswd
## GEN006200 - Permissions of smbpasswd
## GEN006220 - smb.conf file configuration

###### NNTP is not installed. Following go as N/A
## GEN006240 - Disable all INN packages
## GEN006260 - hosts.nntp permissions
## GEN006280 - hosts.nntp.nolimit permissions
## GEN006300 - nnrp.access permissions
## GEN006320 - passwd.nntp permissions
## GEN006340 - owner of /etc/news files
## GEN006360 - group owner of /etc/news files

## NIS/NIS+/YP server - Not Applicable
## GEN006380/6400/6420/6440/6460

## GEN006480 - AIDE is configured as host based IDS

## GEN006500 - Owned by root
## (GEN006520: CAT II) (Previously â G189) The SA will ensure security tools
## and databases have permissions of 740, or more restrictive.

## IPTABLES
chmod 740 /etc/rc.d/init.d/iptables /sbin/iptables
chmod 600 /etc/sysconfig/iptables /etc/sysconfig/iptables-config
chown root:root /etc/rc.d/init.d/iptables /sbin/iptables
chown root:root /etc/sysconfig/iptables /etc/sysconfig/iptables-config
## AIDE
chmod 600 /etc/aide.conf /etc/logrotate.d/aide
find /var/log/aide -xtype f -exec chmod 600 {} \;
find /var/lib/aide -xtype f -exec chmod 600 {} \;
chmod 740 /var/lib/aide /var/log/aide
chown -R root:root /var/lib/aide
chown -R root:root /var/log/aide
chown root:root /etc/aide.conf /etc/logrotate.d/aide

## (GEN006540: CAT II) (Previously – G190) The SA will run vulnerability assessment
## tools at least weekly.
## (GEN006560: CAT II) The SA will ensure vulnerability assessment tools, host-based
## intrusion detection tools, and file system integrity baseline methods notify
##  the SA and the IAO if a security breach or a suspected security breach is discovered.
cat <<'EOF' > /etc/cron.weekly/aide
aide --check --config /etc/aide.conf | mail -s "AIDE Report - EXAMPLE.COM" -S smtp=mail.example.com security@example.com
EOF

## GEN006560 - Site responsibility

## (GEN006580: CAT II) (Previously – G196) The SA will ensure an access control program
## (e.g., TCP_WRAPPERS) is implemented on all UNIX hosts connected to a network.
## In built for RHEL6 - condition satisfied
## (GEN006600: CAT II) (Previously – G197) The SA will ensure an access control program
## (e.g., TCP_WRAPPERS) is configured to log each system access attempt.
## Checks do not seem to care about Linux implementations

## (GEN006620: CAT II) The SA will ensure an access control program (e.g.,
## TCP_WRAPPERS) hosts.deny and hosts.allow files (or equivalent) are used to
## grant or deny system access to specific hosts.
echo '==================================================='
echo ' Patching GEN006620: Set hosts.deny file'
echo '==================================================='
echo "ALL: ALL" > /etc/hosts.deny
## This must be modified based on the network environment
echo "ALL: ALL" > /etc/hosts.allow

## (LNX00160: CAT II) (Previously â L074) The SA will ensure the grub.conf
## file has permissions of 600, or more restrictive.
echo '==================================================='
echo 'Patching LNX00160: Set grub.conf permissions'
echo '==================================================='
chmod 600 /boot/grub/grub.conf

## LNX00180/LNX00200/LNX00220 - NOT APPLICABLE - NO LILO

## (LNX00220: CAT II) (Previously â L080) The SA will ensure the lilo.conf
## file has permissions of 600 or more restrictive.
## Not Applicable to RHEL6
echo '==================================================='
echo 'Patching LNX00220: Set lilo.conf permissions'
echo '==================================================='
if [ -f /etc/lilo.conf ]
then
        chmod 600 /etc/lilo.conf
fi

## LNX00240 - EXT4 default option is journaling
## LNX00260 - Client responsibility
## LNX00280/LNX00300 - Not Applicable

## (LNX00340: CAT II) (Previously â L142) The SA will delete accounts that
## provide no operational purpose, such as games or operator, and will delete
## the associated software.
echo '==================================================='
echo ' Patching LNX00340: Disable unnecessary accounts.'
echo '==================================================='
/usr/sbin/userdel news
/usr/sbin/userdel operator
/usr/sbin/userdel games
/usr/sbin/userdel gopher
/usr/sbin/userdel ftp


## (LNX00360: CAT II) (Previously â L032) The SA will enable the X server
## âaudit (at level 4) and âs option (with 15 minutes as the timeout time)
## options.
## LNX00380
#echo '==================================================='
#echo 'Patching LNX00360: Set X server options'
#echo '==================================================='
#echo "
#[server-Standard]
#name=Standard server
#command=/usr/bin/Xorg -br -audit 4 -s 15
#flexible=true" >> /etc/gdm/custom.conf
# Above are not applicable becuase X server is not installed.

## (LNX00400: CAT II) (Previously â L044) The SA will ensure the owner of the
## /etc/login.access or /etc/security/access.conf file is root.
## LNX00420 - Group owner for access.conf
## LNX00440 - Permissions for access.conf
echo '==================================================='
echo 'Patching LNX00400: Set access.conf owner'
echo '==================================================='
chown root:root /etc/security/access.conf
chmod 640 /etc/security/access.conf

## LNX00460 - Limit access to specific users - Do it MANUALLY

## LNX00480 / LNX00500 / LNX00520
## Ownership and permissions for /etc/sysctl.conf
chown root:root /etc/sysctl.conf
chmod 600 /etc/sysctl.conf

## LNX00600 - pam_console.so not mentioned in system-auth files

## LNx00620 / LNX00640 / LNX00660
## Ownership and permissions for /etc/securetty
chown root:root /etc/securetty
chmod 640 /etc/securetty

## LNX00680 - Not Applicable - real player not installed

######################################################################################
########################### CATEGORY III #############################################
######################################################################################


## (GEN001080: CAT III) (Previously â G229) The SA will ensure the root shell
## is not located in /usr if /usr is partitioned.
echo '==================================================='
echo 'Patching GEN001080: Set root shell out of /usr'
echo '==================================================='
/usr/sbin/usermod -s /bin/bash root

## (GEN001280: CAT III) (Previously â G042) The SA will ensure all manual page
## files (i.e.,files in the man and cat directories) have permissions of 644,
## or more restrictive.
echo '==================================================='
echo ' Patching GEN001280: Set manual page permissions'
echo '==================================================='
find /usr/share/man -type f -exec chmod 644 {} \;
find /usr/share/info -type f -exec chmod 644 {} \;


## (GEN001780: CAT III) (Previously â G112) The SA will ensure global
## initialization files contain the command mesg ân.
echo '==================================================='
echo 'Patching GEN001780: Add mesg -n to global'
echo '                    initialization files'
echo '==================================================='
for FILE in /etc/{profile,bashrc}; do
        echo "mesg n" >> $FILE
done;

## (GEN003500: CAT III) The SA will ensure core dumps are disabled or
## restricted.
echo '==================================================='
echo 'Patching GEN003500: Disable core dumps'
echo '==================================================='
echo "# Disable Core dumps" >> /etc/security/limits.conf
echo "* - core 0" >> /etc/security/limits.conf
echo "# Disable Core Dumps by SUID programs"
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

## (GEN003520: CAT III) The SA will ensure the owner and group owner of the
## core dump  data directory is root with permissions of 700, or more
## restrictive.
echo '==================================================='
echo ' Patching GEN003520: Set crash log dir permissions'
echo '==================================================='
chown -R root:root /var/crash
chmod -R 700 /var/crash
find /var/crash -type f -exec chmod 600 {} \;

##(GEN003680: CAT III) (Previously – A028) The SA will ensure all network services not required for operations are disabled. Any network services required for operations must be documented with the IAO.
## MANUAL CHECK

## GEN003840 - REXEC - Not Applicable

## (GEN003860: CAT III) (Previously â V046) The SA will ensure finger is not
## enabled.
## Finger no more exists in RHEL6
#echo '==================================================='
#echo 'Patching GEN003860: Disable finger daemon'
#echo '==================================================='
#/sbin/chkconfig finger off

## GEN003865 - Not in documentation but scripts are scanning this one
## these packages are also removed from kickstart file
for SNIFFER in ethereal wireshark tshark tcpdump snoop nc
do
        rpm -qa | grep -i $SNIFFER
        if [ $? -ne 1 ]; then
                yum -y remove $SNIFFER
        fi
done


## (GEN005760: CAT III) (Previously â G179) The SA will ensure the export
## configuration file has permissions of 644, or more restrictive.
echo '==================================================='
echo 'Patching GEN005760: Set permissions of the export'
echo '                    config file'
echo '==================================================='
chmod 644 /etc/exports

## GEN001440 - Its probably better to check rather than assigning a directory in /home

## (GEN001460: CAT IV) (Previously â G052) The SA will ensure all home
## directories defined in the /etc/passwd file exist.
echo '==================================================='
echo 'Patching GEN001460: Create home directories'
echo '==================================================='
for HOMEDIR in `cut -d: -f6 /etc/passwd`; do
        if [  ! -d $HOMEDIR ]
        then
                mkdir $HOMEDIR
        fi
done;


## Sendmail NOT running
## (GEN004440: CAT IV) (Previously â G133) The SA will ensure the sendmail
## logging level (the detail level of e-mail tracing and debugging
## information) in the sendmail.cf file is set to a value no lower than
## nine (9).
#echo '==================================================='
#echo 'Patching GEN004440: Set sendmail logging level'
#echo '==================================================='
#sed -i '/LogLevel/ c\O LogLevel=9' /etc/mail/sendmail.cf 
