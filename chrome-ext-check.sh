#!/bin/bash
#
####################################
# Malicious Chrome Extension Check #
# Mallory Bowes-Brown              #
# mallory@acceptablyparanoid.me    #
####################################

# This is a simple script to check for compromised Google Chrome Extensions.
# I've put together a meta list of all the compromised extension IDs up on Github.  I update the 
# list on new reports of compromised extensions when the ID is present.

# Please see https://github.com/mallorybowes/chrome-mal-ids for the current source list of the malicious IDs.

# This script is licensed under the CC Attribution License.  Please see https://creativecommons.org/licenses/by/4.0/ for terms.
# Prerequisites: mktemp, wget, tidy, awk, wc, ls, trap, bash, internet connection 

## --Script starts here-- ##

# Change the below paths for your own machine
# The current path is the default for Ubuntu / Debian repository Chrome installations
EXTENSIONPATH=~/.config/google-chrome/Default/Extensions
EXTENSIONLIST=$(mktemp) || exit 1
COMPROMISEDEXTENSIONS=$(mktemp) || exit 1
SOURCEURL=https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.csv
i=0

# Remove temp files on script completion
trap 'rm -f "$COMPROMISEDEXTENSIONS" "$EXTENSIONLIST" ' EXIT

# Populate the current user's extension list
ls $EXTENSIONPATH > $EXTENSIONLIST

# Grab the current list off Github
wget --quiet -O $COMPROMISEDEXTENSIONS $SOURCEURL 

# How many malicious extensions did we get?
num=`wc -l $COMPROMISEDEXTENSIONS | awk ' { print $1 } '`
echo "Going to check for $num currently known malicious extensions.  Please see my Github page for extension list details."

# search function
for extension in `cat $COMPROMISEDEXTENSIONS` 
do
 hit=`cat $EXTENSIONLIST | grep -ic $extension`
 if test $hit -eq 1
 then
   name=`wget --quiet -O /dev/stdout https://chrome.google.com/webstore/detail/$extension | tidy -q --show-warnings false | grep e-f-w | grep ^\<h1 | awk -F\> ' { print $2 } ' | tr "\<\/h1" " "`
 echo "Compromised extension: Name: $name  ID:$extension"
 ((i=i+1))
 fi
done

if test $i -eq 0 
then
  echo "No malicious extensions found."
else
  echo "Extensions without names were removed from the Chrome Store but there are legitimate extentions whose names do not resolve from the Chrome Web Store.  These extensions can be found at https://www.jamieweb.net/info/chrome-extension-ids/"
fi
