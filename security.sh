# Library: sec
# Script: security.sh
# Purpose: Security manager to control password access.  Uses a mapping to abstract
#     the conversion from a simple code to a variable in Ansible Vault.
#   Other security functions help limit and identify users to PSSA.
#
# Note: Actual passwords are stored in the ansible vault that is password secured
#   When running a script that needs a password, user will be prompted
#     for a password to the vault.  Only Rundeck will be allowed to
#     automatically provide the vault password, allowing scripts to be scheduled.
#
# CB: Nate Werner
# Created: 11/22/2017
#
#### Functions
#
#  Security typeCodes for (Gen)eral services:
#       "f5","connect","rundeck","ps","vault"
#
#  Security typeCodes for DB services:
#       fsprd,csprd,hrprd,ihprd, fsnonprd,csnonprd,hrnonprd,ihnonprd
#
#  getandStoreVaultAccess()
#     Retrieves the vault password for ruther uses on local or remote VMs
#     and stores in a encrypted variable to prevent re-prompting for passwords
#
#  getGenSecurity(typeCode, out typePassword)
#     Retrieves the passwords for non DB Services
#
###########################

#includes

# Passwords are stored in the ansible vault and secured with a password.
#  Check password for vault in Password Safe

# Ansible paths
ANSIBLE_HOME=/psoft/ansible

# Password Type Codes passed into functions
PASS_RUNDECK_CODE="rundeck"
PASS_VAULT_CODE="vault"

# Keys to match variable name in Ansible vault
PASS_RUNDECK_KEY="rundeck_api_pass"
PASS_VAULT_KEY="ansible_vault_pass"

function __mapCodetoKey() # typeCode, returns keystring
{
  local typeCode=$1
  local keyString=""

  case "$typeCode" in
    "$PASS_RUNDECK_CODE")
       keyString=$PASS_RUNDECK_KEY
       ;;
    "$PASS_VAULT_CODE")
       keyString=$PASS_VAULT_KEY
       ;;
  esac
  if [ -z "${keyString}" ]; then
    echo "Invalid Password type provided: $typeCode"
    return 1
  else
    echo "${keyString}"
    return 0
  fi
}

# Use this function to get a password for a service that is not app/env specific
#   Applies to services like f5, rundeck, connect, common psoft users etc
function sec::getGenSecurity() #typeCode, out typePassword
{
   local typeCode="$1"
   local varPass=$2
   local currentDate=""
   local VaultPass_File=""
   local passwdKey=""
   local reqPasword=""
   local vaultResult=0

   # Only allow PSSA user access to function
   if sec::isValidUser; then

     # Lookup key from type provided
     passwdKey=$( __mapCodetoKey $typeCode )
     if [ $? -eq 0 ]; then
       # got a valid key, lookup password
       # run ansible to read password from vault

       # Check if Vault password was provided by env var
       if [ -n "$ANSIBLE_VAULT" ]; then
         # create a unique temporary vault password file
         currentDate="$(date +%y%m%d%H%M%S%N )"
         VaultPass_File="$ANSIBLE_HOME/tmp/ggsv_$currentDate"
         # use function getvaultaccess to encrypt the ANSIBLE_VAULT variable
         echo "$ANSIBLE_VAULT" | openssl enc -aes-256-cbc -md sha256 -a -d -salt -pass env:USER 2>/dev/null > $VaultPass_File
         chmod 600 $VaultPass_File
         reqPasword=$( cd $ANSIBLE_HOME && ANSIBLE_LOG_PATH=/dev/null ansible localhost --vault-password-file $VaultPass_File -m debug -a "var=${passwdKey}" | grep "${passwdKey}" | awk -F'"' '{ print $4}' )
       else
         # no password provide, will be prompted
         reqPasword=$( cd $ANSIBLE_HOME && ANSIBLE_LOG_PATH=/dev/null ansible localhost --ask-vault-pass -m debug -a "var=${passwdKey}" | grep "${passwdKey}" | awk -F'"' '{ print $4 }' )
       fi
       vaultResult=$?
       if [ -n "$ANSIBLE_VAULT" ]; then
         rm $VaultPass_File > /dev/null 2>&1
       fi

       if [[ -z "${reqPasword}" || $vaultResult -ne 0 ]]; then
         echo "Unable to retrive password from vault!"
         return 1
       else
         eval "$varPass"'="${reqPasword}"'
         return 0
       fi
     else
       # invalid typeCode
       echo "Invalid type code provided, check options"
       return 1
     fi
   else
     echo "You are not authorized to access psoft security"
     return 1
   fi
}

# Prompts for vault password and stores in encrypted variable
# used my maint library to store vault pass before using for
# other passwords, prevents user needing to be reprompted
# in same session of a maint function.  Works for remote
# function calls by parameter
function sec::getandStoreVaultAccess()
{
   local vaultPass
   local encryptPass=""

   # Bypass if running from RunDeck
   if sec::setRDVaultAccess; then
     return 0
   else
     # Only allow PSSA user access to function
     if sec::isValidUser; then

       if [ -z "$ANSIBLE_VAULT" ]; then
         # Call the security access function for the vault pass
         sec::getGenSecurity "vault" vaultPass
         if [[ $? -ne 0 ]]; then
           return 1
         fi
         encryptPass=$( echo "$vaultPass" | openssl enc -aes-256-cbc -md sha256 -a -salt -pass env:USER )
         export ANSIBLE_VAULT="${encryptPass}"
         return 0
       fi
     else
       echo "You are not authorized to access psoft security"
       return 1
     fi
   fi
}

# Use for when it is passed by env variable (Rundeck)
function sec::setRDVaultAccess()
{
   if [ -n "$RD_OPTION_VAULTPASS" ]; then
     encryptPass=$( echo "$RD_OPTION_VAULTPASS" | openssl enc -aes-256-cbc -md sha256 -a -salt -pass env:USER )
     export ANSIBLE_VAULT="${encryptPass}"
     return 0
   else
     return 1
   fi
}
