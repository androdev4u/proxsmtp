#!/bin/sh

################################################################################
# PROXSMTP SAMPLE SCRIPT
#
# These sample scripts are to give you an idea of how to use proxsmtp
# filtering. They are NOT intended for use on production servers.
#
# A simple proxsmtp script which sends email through spamassassin.
#
# Make sure the option 'FilterType' is set as follows:
#   FilterType: pipe
#
# See proxsmtpd.conf(5) for configuration details
#

# Pipe mail through this command
spamassassin -e

# Now check return value
if [ $? -ne 0 ]; then

	# The last line of output to stderr will be used
	# as an error message when the filter fails
	echo "550 Content Rejected: We don't like spam" >&2

	# Cause the filter to fail, email will be rejected
	exit 1
fi

# Filter success
exit 0
