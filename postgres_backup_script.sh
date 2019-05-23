#!/bin/bash

# Author:		xrpx
# Description:		PostgreSQL backup script for daily DB backups
# Last Modified:	August 18, 2014

# SSH keys need to be set up for passwordless login to server
# SSH keys in default location (~/.ssh/)and run as $BACKUP_USER
# Both servers will have /var/lib/pgsql/backups owned by $BACKUP_USER
# Prod server should have ***TRUST*** relationship for $PG_USER (Or use md5 relationship and add password to all psql statements)
# Set up a cron job to execute this script on production server using the command
# 19 20 * * * sh ./dbbackup.sh >> cron.`date +\%Y-\%m-\%d`.log

# List Configuration Variables
TODAY=`/bin/date +%Y-%m-%d`
PG_USER=root
BACKUP_USER=backupuser
BACKUP_DIR_PROD="/var/lib/pgsql/backups"
BACKUP_DIR_TEST="/var/lib/pgsql/backups"
DAYS_TO_KEEP_ON_TEST=30
TEST_SERVER="backupserverforDB.example.com"

# Output Redirection
exec 2>&1 1>${BACKUP_DIR_PROD}/SCRIPT.${TODAY}.log

# Configuration variables end here
RETVAL='0'

echo "******** PostgreSQL backup for $TODAY ********";

# List databases: Exclude templates, postgres and root
DATABASES=`psql -U ${PG_USER} -t -d template1 -q -c "\l" | awk {'print $1'} | awk '!/(root|template|\:|\||postgres)/'`

echo "Following databases will be backed up:
$DATABASES";

# Backup
if [ ! -d "$BACKUP_DIR_PROD" ]; then
	mkdir ${BACKUP_DIR_PROD}
	echo "Created backup directory: ${BACKUP_DIR_PROD}";
fi

cd ${BACKUP_DIR_PROD}

for DB in ${DATABASES}
do
  pg_dump -U ${PG_USER} $DB > ${BACKUP_DIR_PROD}/${DB}.${TODAY}.sql

  RETVAL=$?

  if [ $RETVAL != 0 ]; then
    echo "$0: ERROR: pg_dump exit with $RETVAL";
  else
    echo "Backup successfully completed for ${DB} on ${TODAY}";
  fi
done

# Transfer backup files to test server
scp -pr * ${BACKUP_USER}@${TEST_SERVER}:${BACKUP_DIR_TEST}/ &

# We must NOT remove DBs until SCP is finished
wait $!

# Don't keep copies on prod server
rm -rf ${BACKUP_DIR_PROD}/*

# Keep last 30 days worth and delete rest on Test Server
ssh ${BACKUP_USER}@${TEST_SERVER} BACKUP_DIR_TEST=${BACKUP_DIR_TEST} 'bash -s' <<'ENDSSH'
find ${BACKUP_DIR_TEST} -xtype f -mtime +${DAYS_TO_KEEP_ON_TEST} -exec rm -rf {} \;
ENDSSH

echo "******** End of PostgreSQL backup ********";
exit $RETVAL

# End
