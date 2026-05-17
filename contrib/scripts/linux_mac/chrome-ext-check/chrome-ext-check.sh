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
# Prereqs: awk, wc, ls, bash, curl, uname, internet connection 

## --Script starts here-- ##

SOURCEURL_EXTS="https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-meta.csv"
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
EXTENSIONPATHS=( 
  "${HOME}/.config/google-chrome/Default/Extensions/"
  "${HOME}/snap/brave/current/.config/BraveSoftware/Brave-Browser/Default/Extensions/" 
  "${HOME}/Library/Application Support/Google/Chrome/Default/Extensions/"
  "${HOME}/Library/Application Support/BraveSoftware/Brave-Browser-Beta/Default/Extensions/" 
)

EXISTINGPATHS=()
for path in "${EXTENSIONPATHS[@]}"; do
  if [ -e "${path}" ]; then
    EXISTINGPATHS+=("${path}")
  fi
done

# Grab the current list off Github if it's newer than the temporary one we have (curl -z)
curl -s -z /tmp/bad.csv "${SOURCEURL_EXTS}" -o /tmp/bad-chrome-extensions.csv
# read them in to an array , split on \n
IFS=$'\n' read -d '' -r -a compromisedextensions < /tmp/bad-chrome-extensions.csv

# check that we got the "right" file by checking the first line
if [[ "${compromisedextensions[0]}" != "EXTID,EXTID-NAME,DATE-DIS,DATE-ADD,SOURCE,ARTICLE,ADD-SOURCES,CONTRIB,CONTRIB-METHOD,CONFIRM-MAL,REPORTED-MAL,NOTES" ]]
then
  echo "Something went wrong in the download (maybe a proxy?) so try running the script again."
  exit 1
fi

# How many malicious extensions did we get?
echo -e "Going to check for ${#compromisedextensions[@]} currently known malicious extensions. \nPlease see my Github page (https://github.com/mallorybowes/chrome-mal-ids) for extension list details."

# Search function
for _extensionline in "${compromisedextensions[@]}"}
do
  # check each of the extesnions paths we have found
  for _existingpath in "${EXISTINGPATHS[@]}"; do
    # the {$variable%%,} is bash trickery to remove the longest matching suffix, so we just drop everything after the first , to get the ID
    if [[ -e "${_existingpath}${_extensionline%%,*}" ]]; then
      # if we find something, split the line on , into an array called found
      IFS=',' read -r -a found <<< "$_extensionline"
      echo 
      echo "We found something suspicious at ${_existingpath}${_extensionline%%,*}"
      echo "Name: ${found[1]}"
      echo "Source: ${found[4]}"
      echo "More info: ${found[5]}"
      echo
      # Increment # of malicious extensions found 
      ((i=i+1))
    fi
  done
done

# Put up some summary information
if [[ $i == 0 ]]
then
  echo "No malicious extensions found."
else
  echo "There were $i malicious extensions found."
fi
