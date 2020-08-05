#!/bin/bash
set -x
#
####################################
# Chrome Malicious Extension Check #
####################################

# This is a simple script to check for known compromised Google Chrome Extensions.
# I've put together a meta-list of all the compromised extension IDs I could find on Github.  Updates to the 
# list happen on new reports of compromised extensions and when the ID is present or can be derived.

# Please see https://github.com/mallorybowes/chrome-mal-ids for the current source list of the malicious IDs.

# This script is licensed under the CC Attribution License if included in any commercial endeavor.  Please see https://creativecommons.org/licenses/by/4.0/ for terms.
# Prereqs: mktemp, wget, tidy, awk, sha256sum, wc, ls, tr, grep, trap, bash, internet connection 

## --Script starts here-- ##

# Change the below paths for your own machine
# The current path is the default for Ubuntu / Debian repository Chrome installations
EXTENSIONPATH=${EXTENSIONPATH="${HOME}/.config/google-chrome/Default/Extensions"}
SOURCEURL_EXTS="https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.csv"
SOURCEURL_CHKSUM="https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-chksum.txt"
i=0

# Rudimentary "progress script" (just echo the debug...)
if [[ "${1}" == "-v" ]]
then
  set -x
elif [[ -n "${1}" ]]
then
  echo 'Only one arg to pass:  -v:  turn on debug for a "progress bar" of sorts...'
  exit 1
fi 

# Populate the current user's extension list
EXTENSIONLIST="$( ls ${EXTENSIONPATH} )"

# Grab the current list off Github
echo "Downloading latest extensions file..."
COMPROMISEDEXTENSIONS=$( curl -s "${SOURCEURL_EXTS}" )
echo "Downloading latest checksum file..."
CHKSUM=$( curl -s "${SOURCEURL_CHKSUM}" )

# on mac: ${"$(echo $COMPROMISEDEXTENSIONS| shasum -a 256 -p )"%% *}
if [[ "${CHKSUM}" =~ ${"$(echo $COMPROMISEDEXTENSIONS | sha256sum )"%% *} ]]
then
  echo "Something went wrong in the download so try running the script again.  Cleaning old files and bailing."
  exit 1
else
  echo "Checksum passed.  Continuing extension check..."
fi

# How many malicious extensions did we get?
num=${"$( echo $COMPROMISEDEXTENSIONS | wc -l )"## * }
echo -e "Going to check for ${num} currently known malicious extensions. \nPlease see my Github page (https://github.com/mallorybowes/chrome-mal-ids) for extension list details."

# Search function
for extension in "$COMPROMISEDEXTENSIONS" 
do
   if [[ "${EXTENSIONLIST}" =~ "${extension}" ]]
     then
     # Scrape the user friendly name from the Chrome Web Store
     name=`wget --quiet -O /dev/stdout https://chrome.google.com/webstore/detail/$extension | tidy -q --show-warnings false | grep e-f-w | grep ^\<h1 | awk -F\> ' { print $2 } ' | tr "\<\/h1" " "`
     echo "Compromised extension: Name: $name  ID:$extension"
     # Increment # of malicious extensions found 
     ((i=i+1))
   fi
done

# Put up some summary information
if [[ $i == 0 ]]
then
  echo "No malicious extensions found."
else
  echo "There were $i malicious extensions found.  Extensions without names were removed from the Chrome Store but there are legitimate extensions whose names do not resolve from the Chrome Web Store.  Most of these extensions can be found at https://www.jamieweb.net/info/chrome-extension-ids/"
fi
