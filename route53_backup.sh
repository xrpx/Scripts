#!/usr/bin/env bash

# Author:		xrpx
# Description:		Backup DNS zones in AWS Route53 service
# Last modified: 	August 18, 2014

# Dependencies
# apt-get install python-pip will install python boto and other pre-requisites
# pip install cli53


##### Configuration #########
export PATH=$PATH:/usr/local/bin
ZONES=("abc.com" "xyz.com")
GIT_DIR="/opt/git"
BAK_DIR="/var/log/route53_backup/logs"
DATA_DIR="/opt/backup/route53_backup"
DATE=`date +%Y%m%d%H%M`
RETVAL='0'
#############################

# Output Redirection
exec 2>&1 1>${BAK_DIR}/SCRIPT.${DATE}.log
echo "Backup for ${DATE}"
echo "Starting AWS Route 53 Zone Transfer using CLI53..."

# Update GIT first
cd ${GIT_DIR}
git pull --rebase
wait $!

# CLI53 exports route 53 entries in BIND format
for i in ${ZONES[*]}
do 
    cli53 export ${i} > ${DATA_DIR}/${i}-${DATE}.BIND
    RETVAL=$?
    echo "Backup completed for zone ${i}."
done
wait $!

# Keep 90 days worth data on server
find ${DATA_DIR} -xtype f -mtime +90 -exec rm -rf {} \;
echo "Clenaup completed. Backups more than 90 days old have been removed."
wait $!

# Git repo sync
git add .
wait $!
git commit -m "Nightly backup for AWS Route53 on ${DATE}"
wait $!
git push
wait $!

exit $RETVAL
