#!/bin/sh

################################################################################
# PROXSMTP SAMPLE SCRIPT
#
# These sample scripts are to give you an idea of how to use proxsmtp
# filtering. They are NOT intended for use on production servers.
#
# A simple proxsmtp script which replaces the subject line with one
# containing the senders email address. Uses the 'formail' command
# that comes with the 'procmail' package.
#
# Make sure the option 'FilterType' is set as follows:
#   FilterType: pipe
#
# See proxsmtpd.conf(5) for configuration details
#

# Pipe the email through this command
formail -i "Subject: Changed subject from $SENDER ..."

# Filter success
exit 0