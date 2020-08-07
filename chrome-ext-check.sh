#!/bin/bash
#
####################################
# Chrome Malicious Extension Check #
####################################

# This is a simple script to check for known compromised Google Chrome Extensions.
# I've put together a meta-list of all the compromised extension IDs I could find on Github.  Updates to the 
# list happen on new reports of compromised extensions and when the ID is present or can be derived.

# Please see https://github.com/mallorybowes/chrome-mal-ids for the current source list of the malicious IDs.

# This script is licensed under the CC Attribution License if included in any commercial endeavor.  Please see https://creativecommons.org/licenses/by/4.0/ for terms.
# Prereqs: awk, sha256sum, wc, ls, bash, curl, uname, internet connection 

## --Script starts here-- ##

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

# Which OS are we running on?
_hostos=$( uname )

# Populate the current user's extension list
if [[ $_hostos =~ "Darwin" ]]
then
	# On Mac extensions are found in:
	# /Library/Application Support/Google/Chrome/External Extensions
	# ${HOME}/Library/Application Support/Google/Chrome/*/Extensions
	EXTENSIONPATH=${EXTENSIONPATH="${HOME}/Library/Application Support/Google/Chrome/Default/Extensions"}
	extensionlist=$( ls "${EXTENSIONPATH}" )
else
	# Change the below paths for your own machine
	# The current path is the default for Ubuntu / Debian repository Chrome installations
	EXTENSIONPATH=${EXTENSIONPATH="${HOME}/.config/google-chrome/Default/Extensions"}
	extensionlist=$( ls "${EXTENSIONPATH}" )
fi

# Grab the current list off Github
echo "Downloading latest extensions file..."
compromisedextensions=$( curl -s "${SOURCEURL_EXTS}" )
echo "Downloading latest checksum file..."
chksum=$( curl -s "${SOURCEURL_CHKSUM}" )

if [[ $_hostos =~ "Darwin" ]]
then
	_chksum=$(echo "${compromisedextensions}" | shasum -a 256 -p )
else
	_chksum=$(echo "${compromisedextensions}" | sha256sum )
fi

if [[ "${chksum}" =~ ${_chksum%% * } ]]
then
  echo "Something went wrong in the download so try running the script again.  Cleaning old files and bailing."
  exit 1
else
  echo "Checksum passed.  Continuing extension check..."
fi

# How many malicious extensions did we get?
_numext=$( echo "${compromisedextensions}" | wc -l )
_numext=${_numext## * }
echo -e "Going to check for ${_numext} currently known malicious extensions. \nPlease see my Github page (https://github.com/mallorybowes/chrome-mal-ids) for extension list details."

# Search function
for _extensionid in ${compromisedextensions}
do
   if [[ "${extensionlist}" =~ ${_extensionid} ]]
     then
     # Scrape the user friendly name from the Chrome Web Store
     _extname=$( curl -sL https://chrome.google.com/webstore/detail/"${_extensionid}" | awk '/h1 class="e-f-w"/{match($0,/<h1 class="e-f-w">[^<]*</); s = substr($0, RSTART, RLENGTH); gsub(/<h1 class="e-f-w">/, "", s); gsub(/</, "", s); print s}' )
     echo "Compromised extension: Name: ${_extname}  ID:${_extensionid}"
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
