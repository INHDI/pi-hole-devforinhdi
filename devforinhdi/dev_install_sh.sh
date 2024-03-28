#!/usr/bin/env bash
set -e
export PATH+=':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

######## VARIABLES #########
# For better maintainability, we store as much information that can change in variables
# This allows us to make a change in one place that can propagate to all instances of the variable
# These variables should all be GLOBAL variables, written in CAPS
# Local variables will be in lowercase and will exist only within functions
# It's still a work in progress, so you may see some variance in this guideline until it is complete

# Dialog result codes
# dialog code values can be set by environment variables, we only override if
# the env var is not set or empty.
: "${DIALOG_OK:=0}"
: "${DIALOG_CANCEL:=1}"
: "${DIALOG_ESC:=255}"

# List of supported DNS servers
DNS_SERVERS=$(
    cat <<EOM
Google (ECS, DNSSEC);8.8.8.8;8.8.4.4;2001:4860:4860:0:0:0:0:8888;2001:4860:4860:0:0:0:0:8844
Cloudflare (DNSSEC);1.1.1.1;1.0.0.1;2606:4700:4700::1111;2606:4700:4700::1001
EOM
)

# Location for final installation log storage
installLogLoc="/etc/pihole/install.log"
# This is an important file as it contains information specific to the machine it's being installed on
setupVars="/etc/pihole/setupVars.conf"
# Pi-hole uses lighttpd as a Web server, and this is the config file for it
lighttpdConfig="/etc/lighttpd/lighttpd.conf"
# This is a file used for the colorized output
coltable="/opt/pihole/COL_TABLE"

# Root of the web server
webroot="/var/www/html"

# Check if the os is supported
checkOs="Ubuntu=20,22,23"

webInterfaceGitUrl="https://github.com/pi-hole/web.git"
webInterfaceDir="${webroot}/admin"
piholeGitUrl="https://github.com/pi-hole/pi-hole.git"
PI_HOLE_LOCAL_REPO="/etc/.pihole"
# List of pihole scripts, stored in an array
PI_HOLE_FILES=(chronometer list piholeDebug piholeLogFlush setupLCD update version gravity uninstall webpage)
# This directory is where the Pi-hole scripts will be installed
PI_HOLE_INSTALL_DIR="/opt/pihole"
PI_HOLE_CONFIG_DIR="/etc/pihole"
PI_HOLE_BIN_DIR="/usr/local/bin"
FTL_CONFIG_FILE="${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf"
if [ -z "$useUpdateVars" ]; then
    useUpdateVars=false
fi

adlistFile="/etc/pihole/adlists.list"

# Pi-hole needs an IP address; to begin, these variables are empty since we don't know what the IP is until this script can run
IPV4_ADDRESS=${IPV4_ADDRESS}
IPV6_ADDRESS=${IPV6_ADDRESS}
# Give settings their default values. These may be changed by prompts later in the script.
QUERY_LOGGING=true
INSTALL_WEB_INTERFACE=true
PRIVACY_LEVEL=0
CACHE_SIZE=10000

if [ -z "${USER}" ]; then
    USER="$(id -un)"
fi

# dialog dimensions: Let dialog handle appropriate sizing.
r=20
c=70

######## Undocumented Flags. Shhh ########
# These are undocumented flags; some of which we can use when repairing an installation
# The runUnattended flag is one example of this
reconfigure=false
runUnattended=false
INSTALL_WEB_SERVER=true
# Check arguments for the undocumented flags
for var in "$@"; do
    case "$var" in
    "--reconfigure") reconfigure=true ;;
    "--unattended") runUnattended=true ;;
    "--disable-install-webserver") INSTALL_WEB_SERVER=false ;;
    esac
done

if [[ -f "${coltable}" ]]; then
    # source it
    source "${coltable}"
# Otherwise,
else
    # Set these values so the installer can still run in color
    COL_NC='\e[0m' # No Color
    COL_LIGHT_GREEN='\e[1;32m'
    COL_LIGHT_RED='\e[1;31m'
    TICK="[${COL_LIGHT_GREEN}👍${COL_NC}]"
    CROSS="[${COL_LIGHT_RED}👎${COL_NC}]"
    INFO="[🔍]"
    DONE="${COL_LIGHT_GREEN} Hoàn thành rồi!${COL_NC}"
    OVER="\\r\\033[K"
fi

# A simple function that just echoes out our logo in ASCII format
# This lets users know that it is a FIS, LLC product

show_ascii_berry() {
    echo -e "
        ${COL_LIGHT_GREEN}.;;,.
        .ccccc:,.
         :cccclll:.      ..,,
          :ccccclll.   ;ooodc
           'ccll:;ll .oooodc
             .;cll.;;looo:.
                 ${COL_LIGHT_RED}.. ','.
                .',,,,,,'.
              .',,,,,,,,,,.
            .',,,,,,,,,,,,....
          ....''',,,,,,,'.......
        .........  ....  .........
        ..........      ..........
        ..........      ..........
        .........  ....  .........
          ........,,,,,,,'......
            ....',,,,,,,,,,,,.
               .',,,,,,,,,'.
                .',,,,,,'.
                  ..'''.${COL_NC}
"
}

is_command() {
    # Checks to see if the given command (passed as a string argument) exists on the system.
    # The function returns 0 (success) if the command exists, and 1 if it doesn't.
    local check_command="$1"

    command -v "${check_command}" >/dev/null 2>&1
}

os_check() {
    # Function to check the detected operating system and version against the expected values.
    local valid_os valid_version detected_os detected_version
    detected_os=$(grep '^ID=' /etc/os-release | cut -d '=' -f2 | tr -d '"')
    detected_version=$(grep VERSION_ID /etc/os-release | cut -d '=' -f2 | tr -d '"')

    # Compare detected_os & detected_version with checkOs
    if [[ "${checkOs}" == *"${detected_os}"* ]]; then
        valid_os=true
        if [[ "${checkOs}" == *"${detected_version}"* ]]; then
            valid_version=true
        else
            valid_version=false
        fi
    else
        valid_os=false
    fi

    if [ "$valid_version" = false ]; then
        printf "  %b %bUnsupported OS detected%b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${COL_NC}"
        printf "  %b Os Currently Detected: %b%s %s%b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${detected_os}" "${detected_version}" "${COL_NC}"
        printf "  %bThis installer is for %bUbuntu 20,22,23%b\\n" "${INFO}" "${COL_LIGHT_GREEN}" "${COL_NC}"
        exit 1

    else
        printf "  %b %bSupported OS detected%b\\n" "${TICK}" "${COL_LIGHT_GREEN}" "${COL_NC}"
    fi
}

make_temporary_log() {
    # Create a random temporary file for the log
    TEMPLOG=$(mktemp /tmp/pihole_temp.XXXXXX)
    # Open handle 3 for templog
    # https://stackoverflow.com/questions/18460186/writing-outputs-to-log-file-and-console
    exec 3>"$TEMPLOG"
    # Delete templog, but allow for addressing via file handle
    # This lets us write to the log without having a temporary file on the drive, which
    # is meant to be a security measure so there is not a lingering file on the drive during the install process
    rm "$TEMPLOG"
}

# SELinux
checkSelinux() {
    local DEFAULT_SELINUX
    local CURRENT_SELINUX
    local SELINUX_ENFORCING=0
    # Check for SELinux configuration file and getenforce command
    if [[ -f /etc/selinux/config ]] && is_command getenforce; then
        # Check the default SELinux mode
        DEFAULT_SELINUX=$(awk -F= '/^SELINUX=/ {print $2}' /etc/selinux/config)
        case "${DEFAULT_SELINUX,,}" in
        enforcing)
            printf "  %b %bDefault SELinux: %s%b\\n" "${CROSS}" "${COL_RED}" "${DEFAULT_SELINUX,,}" "${COL_NC}"
            SELINUX_ENFORCING=1
            ;;
        *) # 'permissive' and 'disabled'
            printf "  %b %bDefault SELinux: %s%b\\n" "${TICK}" "${COL_GREEN}" "${DEFAULT_SELINUX,,}" "${COL_NC}"
            ;;
        esac
        # Check the current state of SELinux
        CURRENT_SELINUX=$(getenforce)
        case "${CURRENT_SELINUX,,}" in
        enforcing)
            printf "  %b %bCurrent SELinux: %s%b\\n" "${CROSS}" "${COL_RED}" "${CURRENT_SELINUX,,}" "${COL_NC}"
            SELINUX_ENFORCING=1
            ;;
        *) # 'permissive' and 'disabled'
            printf "  %b %bCurrent SELinux: %s%b\\n" "${TICK}" "${COL_GREEN}" "${CURRENT_SELINUX,,}" "${COL_NC}"
            ;;
        esac
    else
        echo -e "  ${INFO} ${COL_GREEN}SELinux not detected${COL_NC}"
    fi
    # Exit the installer if any SELinux checks toggled the flag
    if [[ "${SELINUX_ENFORCING}" -eq 1 ]] && [[ -z "${PIHOLE_SELINUX}" ]]; then
        printf "  Pi-hole does not provide an SELinux policy as the required changes modify the security of your system.\\n"
        printf "  Please refer to https://wiki.centos.org/HowTos/SELinux if SELinux is required for your deployment.\\n"
        printf "      This check can be skipped by setting the environment variable %bPIHOLE_SELINUX%b to %btrue%b\\n" "${COL_LIGHT_RED}" "${COL_NC}" "${COL_LIGHT_RED}" "${COL_NC}"
        printf "      e.g: export PIHOLE_SELINUX=true\\n"
        printf "      By setting this variable to true you acknowledge there may be issues with Pi-hole during or after the install\\n"
        printf "\\n  %bSELinux Enforcing detected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
        exit 1
    elif [[ "${SELINUX_ENFORCING}" -eq 1 ]] && [[ -n "${PIHOLE_SELINUX}" ]]; then
        printf "  %b %bSELinux Enforcing detected%b. PIHOLE_SELINUX env variable set - installer will continue\\n" "${INFO}" "${COL_LIGHT_RED}" "${COL_NC}"
    fi
}

update_package_cache() {
    # Update package cache on apt based OSes. Do this every time since
    # it's quick and packages can be updated at any time.

    # Local, named variables
    local str="Update local cache of available packages"
    printf "  %b %s..." "${INFO}" "${str}"
    # Create a command from the package cache variable
    if eval "${UPDATE_PKG_CACHE}" &>/dev/null; then
        printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
    else
        # Otherwise, show an error and exit

        # In case we used apt-get and apt is also available, we use this as recommendation as we have seen it
        # gives more user-friendly (interactive) advice
        if [[ ${PKG_MANAGER} == "apt-get" ]] && is_command apt; then
            UPDATE_PKG_CACHE="apt update"
        fi
        printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
        printf "  %b Error: Unable to update package cache. Please try \"%s\"%b\\n" "${COL_LIGHT_RED}" "sudo ${UPDATE_PKG_CACHE}" "${COL_NC}"
        return 1
    fi
}

# Compatibility
package_manager_detect() {
    # TODO - pull common packages for both distributions out into a common variable, then add
    # the distro-specific ones below.

    # First check to see if apt-get is installed.
    if is_command apt-get; then
        # Set some global variables here
        # We don't set them earlier since the installed package manager might be rpm, so these values would be different
        PKG_MANAGER="apt-get"
        # A variable to store the command used to update the package cache
        UPDATE_PKG_CACHE="${PKG_MANAGER} update"
        # The command we will use to actually install packages
        PKG_INSTALL=("${PKG_MANAGER}" -qq --no-install-recommends install)
        # grep -c will return 1 if there are no matches. This is an acceptable condition, so we OR TRUE to prevent set -e exiting the script.
        PKG_COUNT="${PKG_MANAGER} -s -o Debug::NoLocking=true upgrade | grep -c ^Inst || true"
        # Update package cache
        update_package_cache || exit 1
        # Check for and determine version number (major and minor) of current php install
        local phpVer="php"
        if is_command php; then
            phpVer="$(php <<<"<?php echo PHP_VERSION ?>")"
            # Check if the first character of the string is numeric
            if [[ ${phpVer:0:1} =~ [1-9] ]]; then
                printf "  %b Existing PHP installation detected : PHP version %s\\n" "${INFO}" "${phpVer}"
                printf -v phpInsMajor "%d" "$(php <<<"<?php echo PHP_MAJOR_VERSION ?>")"
                printf -v phpInsMinor "%d" "$(php <<<"<?php echo PHP_MINOR_VERSION ?>")"
                phpVer="php$phpInsMajor.$phpInsMinor"
            else
                printf "  %b No valid PHP installation detected!\\n" "${CROSS}"
                printf "  %b PHP version : %s\\n" "${INFO}" "${phpVer}"
                printf "  %b Aborting installation.\\n" "${CROSS}"
                exit 1
            fi
        fi
        # Packages required to perform the os_check (stored as an array)
        OS_CHECK_DEPS=(grep dnsutils)
        # Packages required to run this install script (stored as an array)
        INSTALLER_DEPS=(git iproute2 dialog ca-certificates)
        # Packages required to run Pi-hole (stored as an array)
        PIHOLE_DEPS=(cron curl iputils-ping psmisc sudo unzip idn2 libcap2-bin dns-root-data libcap2 netcat-openbsd procps jq)
        # Packages required for the Web admin interface (stored as an array)
        # It's useful to separate this from Pi-hole, since the two repos are also setup separately
        PIHOLE_WEB_DEPS=(lighttpd "${phpVer}-common" "${phpVer}-cgi" "${phpVer}-sqlite3" "${phpVer}-xml" "${phpVer}-intl")
        # Prior to PHP8.0, JSON functionality is provided as dedicated module, required by Pi-hole web: https://www.php.net/manual/json.installation.php
        if [[ -z "${phpInsMajor}" || "${phpInsMajor}" -lt 8 ]]; then
            PIHOLE_WEB_DEPS+=("${phpVer}-json")
        fi
        # The Web server user,
        LIGHTTPD_USER="www-data"
        # group,
        LIGHTTPD_GROUP="www-data"
        # and config file
        LIGHTTPD_CFG="lighttpd.conf.debian"
    else
        # we cannot install required packages
        printf "  %b No supported package manager found\\n" "${CROSS}"
        # so exit the installer
        exit
    fi
}

# Let user know if they have outdated packages on their system and
# advise them to run a package update at soonest possible.
notify_package_updates_available() {
    # Local, named variables
    local str="Checking ${PKG_MANAGER} for upgraded packages"
    printf "\\n  %b %s..." "${INFO}" "${str}"
    # Store the list of packages in a variable
    updatesToInstall=$(eval "${PKG_COUNT}")

    if [[ -d "/lib/modules/$(uname -r)" ]]; then
        if [[ "${updatesToInstall}" -eq 0 ]]; then
            printf "%b  %b %s... up to date!\\n\\n" "${OVER}" "${TICK}" "${str}"
        else
            printf "%b  %b %s... %s updates available\\n" "${OVER}" "${TICK}" "${str}" "${updatesToInstall}"
            printf "  %b %bIt is recommended to update your OS after installing the Pi-hole!%b\\n\\n" "${INFO}" "${COL_LIGHT_GREEN}" "${COL_NC}"
        fi
    else
        printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
        printf "      Kernel update detected. If the install fails, please reboot and try again\\n"
    fi
}

install_dependent_packages() {

    # Install packages passed in via argument array
    # No spinner - conflicts with set -e
    declare -a installArray

    # Debian based package install - debconf will download the entire package list
    # so we just create an array of packages not currently installed to cut down on the
    # amount of download traffic.
    # NOTE: We may be able to use this installArray in the future to create a list of package that were
    # installed by us, and remove only the installed packages, and not the entire list.
    if is_command apt-get; then
        # For each package, check if it's already installed (and if so, don't add it to the installArray)
        for i in "$@"; do
            printf "  %b Checking for %s..." "${INFO}" "${i}"
            if dpkg-query -W -f='${Status}' "${i}" 2>/dev/null | grep "ok installed" &>/dev/null; then
                printf "%b  %b Checking for %s\\n" "${OVER}" "${TICK}" "${i}"
            else
                printf "%b  %b Checking for %s (will be installed)\\n" "${OVER}" "${INFO}" "${i}"
                installArray+=("${i}")
            fi
        done
        # If there's anything to install, install everything in the list.
        if [[ "${#installArray[@]}" -gt 0 ]]; then
            test_dpkg_lock
            # Running apt-get install with minimal output can cause some issues with
            # requiring user input (e.g password for phpmyadmin see #218)
            printf "  %b Processing %s install(s) for: %s, please wait...\\n" "${INFO}" "${PKG_MANAGER}" "${installArray[*]}"
            printf '%*s\n' "${c}" '' | tr " " -
            "${PKG_INSTALL[@]}" "${installArray[@]}"
            printf '%*s\n' "${c}" '' | tr " " -
            return
        fi
        printf "\\n"
        return 0
    fi
    # If there's anything to install, install everything in the list.
    if [[ "${#installArray[@]}" -gt 0 ]]; then
        printf "  %b Processing %s install(s) for: %s, please wait...\\n" "${INFO}" "${PKG_MANAGER}" "${installArray[*]}"
        printf '%*s\n' "${c}" '' | tr " " -
        "${PKG_INSTALL[@]}" "${installArray[@]}"
        printf '%*s\n' "${c}" '' | tr " " -
        return
    fi
    printf "\\n"
    return 0
}

# This function waits for dpkg to unlock, which signals that the previous apt-get command has finished.
test_dpkg_lock() {
    i=0
    printf "  %b Waiting for package manager to finish (up to 30 seconds)\\n" "${INFO}"
    # fuser is a program to show which processes use the named files, sockets, or filesystems
    # So while the lock is held,
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        # we wait half a second,
        sleep 0.5
        # increase the iterator,
        ((i = i + 1))
        # exit if waiting for more then 30 seconds
        if [[ $i -gt 60 ]]; then
            printf "  %b %bError: Could not verify package manager finished and released lock. %b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${COL_NC}"
            printf "       Attempt to install packages manually and retry.\\n"
            exit 1
        fi
    done
    # and then report success once dpkg is unlocked.
    return 0
}
update_dialogs() {
    # If pihole -r "reconfigure" option was selected,
    if [[ "${reconfigure}" = true ]]; then
        # set some variables that will be used
        opt1a="Repair"
        opt1b="This will retain existing settings"
        strAdd="You will remain on the same version"
    else
        # Otherwise, set some variables with different values
        opt1a="Update"
        opt1b="This will retain existing settings."
        strAdd="You will be updated to the latest version."
    fi
    opt2a="Reconfigure"
    opt2b="Resets Pi-hole and allows re-selecting settings."

    # Display the information to the user
    UpdateCmd=$(dialog --no-shadow --keep-tite --output-fd 1 \
        --cancel-label Exit \
        --title "Existing Install Detected!" \
        --menu "\\n\\nWe have detected an existing install.\
    \\n\\nPlease choose from the following options:\
    \\n($strAdd)" \
        "${r}" "${c}" 2 \
        "${opt1a}" "${opt1b}" \
        "${opt2a}" "${opt2b}") || result=$?

    case ${result} in
    "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
        printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
        exit 1
        ;;
    esac

    # Set the variable based on if the user chooses
    case ${UpdateCmd} in
    # repair, or
    "${opt1a}")
        printf "  %b %s option selected\\n" "${INFO}" "${opt1a}"
        useUpdateVars=true
        ;;
    # reconfigure,
    "${opt2a}")
        printf "  %b %s option selected\\n" "${INFO}" "${opt2a}"
        useUpdateVars=false
        ;;
    esac
}

welcomeDialogs() {
    # Display the welcome dialog using an appropriately sized window via the calculation conducted earlier in the script
    dialog --no-shadow --clear --keep-tite \
        --backtitle "Welcome" \
        --title "DNS Sinkhole Made By FIS" \
        --no-button "Exit" --yes-button "Continue" \
        --defaultno \
        --yesno "\\n\\nThis installer will transform your device into domain blacklist blocker." \
        "${r}" "${c}" && result=0 || result="$?"
    case "${result}" in
    "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
        printf "  %b Installer exited at static IP message.\\n" "${INFO}"
        exit 1
        ;;
    esac
}

# Get available interfaces that are UP
get_available_interfaces() {
    # There may be more than one so it's all stored in a variable
    availableInterfaces=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
}

# A function that lets the user pick an interface to use with Pi-hole
chooseInterface() {
    # Turn the available interfaces into a string so it can be used with dialog
    local interfacesList
    # Number of available interfaces
    local interfaceCount

    # POSIX compliant way to get the number of elements in an array
    interfaceCount=$(printf "%s\n" "${availableInterfaces}" | wc -l)

    # If there is one interface,
    if [[ "${interfaceCount}" -eq 1 ]]; then
        # Set it as the interface to use since there is no other option
        PIHOLE_INTERFACE="${availableInterfaces}"
    # Otherwise,
    else
        # Set status for the first entry to be selected
        status="ON"

        # While reading through the available interfaces
        for interface in ${availableInterfaces}; do
            # Put all these interfaces into a string
            interfacesList="${interfacesList}${interface} available ${status} "
            # All further interfaces are deselected
            status="OFF"
        done
        # shellcheck disable=SC2086
        # Disable check for double quote here as we are passing a string with spaces
        PIHOLE_INTERFACE=$(dialog --no-shadow --keep-tite --output-fd 1 \
            --cancel-label "Exit" --ok-label "Select" \
            --radiolist "Choose An Interface (press space to toggle selection)" \
            ${r} ${c} "${interfaceCount}" ${interfacesList})

        result=$?
        case ${result} in
        "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
            # Show an error message and exit
            printf "  %b %s\\n" "${CROSS}" "No interface selected, exiting installer"
            exit 1
            ;;
        esac

        printf "  %b Using interface: %s\\n" "${INFO}" "${PIHOLE_INTERFACE}"
    fi
}

# This lets us prefer ULA addresses over GUA
# This caused problems for some users when their ISP changed their IPv6 addresses
# See https://github.com/pi-hole/pi-hole/issues/1473#issuecomment-301745953
testIPv6() {
    # first will contain fda2 (ULA)
    printf -v first "%s" "${1%%:*}"
    # value1 will contain 253 which is the decimal value corresponding to 0xFD
    value1=$(((0x$first) / 256))
    # value2 will contain 162 which is the decimal value corresponding to 0xA2
    value2=$(((0x$first) % 256))
    # the ULA test is testing for fc00::/7 according to RFC 4193
    if (((value1 & 254) == 252)); then
        # echoing result to calling function as return value
        echo "ULA"
    fi
    # the GUA test is testing for 2000::/3 according to RFC 4291
    if (((value1 & 112) == 32)); then
        # echoing result to calling function as return value
        echo "GUA"
    fi
    # the LL test is testing for fe80::/10 according to RFC 4193
    if (((value1) == 254)) && (((value2 & 192) == 128)); then
        # echoing result to calling function as return value
        echo "Link-local"
    fi
}

# Check an IP address to see if it is a valid one
valid_ip() {
    # Local, named variables
    local ip=${1}
    local stat=1

    # Regex matching one IPv4 component, i.e. an integer from 0 to 255.
    # See https://tools.ietf.org/html/rfc1340
    local ipv4elem="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)"
    # Regex matching an optional port (starting with '#') range of 1-65536
    local portelem="(#(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))?"
    # Build a full IPv4 regex from the above subexpressions
    local regex="^${ipv4elem}\\.${ipv4elem}\\.${ipv4elem}\\.${ipv4elem}${portelem}$"

    # Evaluate the regex, and return the result
    [[ $ip =~ ${regex} ]]

    stat=$?
    return "${stat}"
}

valid_ip6() {
    local ip=${1}
    local stat=1

    # Regex matching one IPv6 element, i.e. a hex value from 0000 to FFFF
    local ipv6elem="[0-9a-fA-F]{1,4}"
    # Regex matching an IPv6 CIDR, i.e. 1 to 128
    local v6cidr="(\\/([1-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])){0,1}"
    # Regex matching an optional port (starting with '#') range of 1-65536
    local portelem="(#(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))?"
    # Build a full IPv6 regex from the above subexpressions
    local regex="^(((${ipv6elem}))*((:${ipv6elem}))*::((${ipv6elem}))*((:${ipv6elem}))*|((${ipv6elem}))((:${ipv6elem})){7})${v6cidr}${portelem}$"

    # Evaluate the regex, and return the result
    [[ ${ip} =~ ${regex} ]]

    stat=$?
    return "${stat}"
}

find_IPv4_information() {
    # Detects IPv4 address used for communication to WAN addresses.
    # Accepts no arguments, returns no values.

    # Named, local variables
    local route
    local IPv4bare

    # Find IP used to route to outside world by checking the the route to Google's public DNS server
    route=$(ip route get 8.8.8.8)

    # Get just the interface IPv4 address
    # shellcheck disable=SC2059,SC2086
    # disabled as we intentionally want to split on whitespace and have printf populate
    # the variable with just the first field.
    printf -v IPv4bare "$(printf ${route#*src })"
    # Get the default gateway IPv4 address (the way to reach the Internet)
    # shellcheck disable=SC2059,SC2086
    printf -v IPv4gw "$(printf ${route#*via })"

    if ! valid_ip "${IPv4bare}"; then
        IPv4bare="127.0.0.1"
    fi

    # Append the CIDR notation to the IP address, if valid_ip fails this should return 127.0.0.1/8
    IPV4_ADDRESS=$(ip -oneline -family inet address show | grep "${IPv4bare}/" | awk '{print $4}' | awk 'END {print}')
}

find_IPv6_information() {
    # Detects IPv6 address used for communication to WAN addresses.
    mapfile -t IPV6_ADDRESSES <<<"$(ip -6 address | grep 'scope global' | awk '{print $2}')"

    # For each address in the array above, determine the type of IPv6 address it is
    for i in "${IPV6_ADDRESSES[@]}"; do
        # Check if it's ULA, GUA, or LL by using the function created earlier
        result=$(testIPv6 "$i")
        # If it's a ULA address, use it and store it as a global variable
        [[ "${result}" == "ULA" ]] && ULA_ADDRESS="${i%/*}"
        # If it's a GUA address, use it and store it as a global variable
        [[ "${result}" == "GUA" ]] && GUA_ADDRESS="${i%/*}"
        # Else if it's a Link-local address, we cannot use it, so just continue
    done

    # Determine which address to be used: Prefer ULA over GUA or don't use any if none found
    # If the ULA_ADDRESS contains a value,
    if [[ -n "${ULA_ADDRESS}" ]]; then
        # set the IPv6 address to the ULA address
        IPV6_ADDRESS="${ULA_ADDRESS}"
        # Show this info to the user
        printf "  %b Found IPv6 ULA address\\n" "${INFO}"
    # Otherwise, if the GUA_ADDRESS has a value,
    elif [[ -n "${GUA_ADDRESS}" ]]; then
        # Let the user know
        printf "  %b Found IPv6 GUA address\\n" "${INFO}"
        # And assign it to the global variable
        IPV6_ADDRESS="${GUA_ADDRESS}"
    # If none of those work,
    else
        printf "  %b Unable to find IPv6 ULA/GUA address\\n" "${INFO}"
        # So set the variable to be empty
        IPV6_ADDRESS=""
    fi
}

# A function to collect IPv4 and IPv6 information of the device
collect_v4andv6_information() {
    find_IPv4_information
    # Echo the information to the user
    printf "  %b IPv4 address: %s\\n" "${INFO}" "${IPV4_ADDRESS}"
    # if `dhcpcd` is used offer to set this as static IP for the device
    if [[ -f "/etc/dhcpcd.conf" ]]; then
        # configure networking via dhcpcd
        getStaticIPv4Settings
    fi
    find_IPv6_information
    printf "  %b IPv6 address: %s\\n" "${INFO}" "${IPV6_ADDRESS}"
}

# A function to choose the upstream DNS provider(s)
setDNS() {
    # Local, named variables
    local DNSSettingsCorrect

    # In an array, list the available upstream providers
    DNSChooseOptions=()
    local DNSServerCount=0
    # Save the old Internal Field Separator in a variable,
    OIFS=$IFS
    # and set the new one to newline
    IFS=$'\n'
    # Put the DNS Servers into an array
    for DNSServer in ${DNS_SERVERS}; do
        DNSName="$(cut -d';' -f1 <<<"${DNSServer}")"
        DNSChooseOptions[DNSServerCount]="${DNSName}"
        ((DNSServerCount = DNSServerCount + 1))
        DNSChooseOptions[DNSServerCount]=""
        ((DNSServerCount = DNSServerCount + 1))
    done
    DNSChooseOptions[DNSServerCount]="Custom"
    ((DNSServerCount = DNSServerCount + 1))
    DNSChooseOptions[DNSServerCount]=""
    # Restore the IFS to what it was
    IFS=${OIFS}
    # In a dialog, show the options
    DNSchoices=$(dialog --no-shadow --keep-tite --output-fd 1 \
        --cancel-label "Exit" \
        --menu "Select Upstream DNS Provider. To use your own, select Custom." "${r}" "${c}" 7 \
        "${DNSChooseOptions[@]}")

    result=$?
    case ${result} in
    "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
        printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
        exit 1
        ;;
    esac

    # Depending on the user's choice, set the GLOBAL variables to the IP of the respective provider
    if [[ "${DNSchoices}" == "Custom" ]]; then
        # Loop until we have a valid DNS setting
        until [[ "${DNSSettingsCorrect}" = True ]]; do
            # Signal value, to be used if the user inputs an invalid IP address
            strInvalid="Invalid"
            if [[ ! "${PIHOLE_DNS_1}" ]]; then
                if [[ ! "${PIHOLE_DNS_2}" ]]; then
                    # If the first and second upstream servers do not exist, do not prepopulate an IP address
                    prePopulate=""
                else
                    # Otherwise, prepopulate the dialogue with the appropriate DNS value(s)
                    prePopulate=", ${PIHOLE_DNS_2}"
                fi
            elif [[ "${PIHOLE_DNS_1}" ]] && [[ ! "${PIHOLE_DNS_2}" ]]; then
                prePopulate="${PIHOLE_DNS_1}"
            elif [[ "${PIHOLE_DNS_1}" ]] && [[ "${PIHOLE_DNS_2}" ]]; then
                prePopulate="${PIHOLE_DNS_1}, ${PIHOLE_DNS_2}"
            fi

            # Prompt the user to enter custom upstream servers
            piholeDNS=$(dialog --no-shadow --keep-tite --output-fd 1 \
                --cancel-label "Exit" \
                --backtitle "Specify Upstream DNS Provider(s)" \
                --inputbox "Enter your desired upstream DNS provider(s), separated by a comma.\
                    If you want to specify a port other than 53, separate it with a hash.\
                    \\n\\nFor example '8.8.8.8, 8.8.4.4' or '127.0.0.1#5335'" \
                "${r}" "${c}" "${prePopulate}")

            result=$?
            case ${result} in
            "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
                printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
                exit 1
                ;;
            esac

            # Clean user input and replace whitespace with comma.
            piholeDNS=$(sed 's/[, \t]\+/,/g' <<<"${piholeDNS}")

            # Separate the user input into the two DNS values (separated by a comma)
            printf -v PIHOLE_DNS_1 "%s" "${piholeDNS%%,*}"
            printf -v PIHOLE_DNS_2 "%s" "${piholeDNS##*,}"

            # If the first DNS value is invalid or empty, this if statement will be true and we will set PIHOLE_DNS_1="Invalid"
            if ! valid_ip "${PIHOLE_DNS_1}" || [[ ! "${PIHOLE_DNS_1}" ]]; then
                PIHOLE_DNS_1=${strInvalid}
            fi
            # If the second DNS value is invalid or empty, this if statement will be true and we will set PIHOLE_DNS_2="Invalid"
            if ! valid_ip "${PIHOLE_DNS_2}" && [[ "${PIHOLE_DNS_2}" ]]; then
                PIHOLE_DNS_2=${strInvalid}
            fi
            # If either of the DNS servers are invalid,
            if [[ "${PIHOLE_DNS_1}" == "${strInvalid}" ]] || [[ "${PIHOLE_DNS_2}" == "${strInvalid}" ]]; then
                # explain this to the user,
                dialog --no-shadow --keep-tite \
                    --title "Invalid IP Address(es)" \
                    --backtitle "Invalid IP" \
                    --msgbox "\\nOne or both of the entered IP addresses were invalid. Please try again.\
                        \\n\\nInvalid IPs: ${PIHOLE_DNS_1}, ${PIHOLE_DNS_2}" \
                    "${r}" "${c}"

                # set the variables back to nothing,
                if [[ "${PIHOLE_DNS_1}" == "${strInvalid}" ]]; then
                    PIHOLE_DNS_1=""
                fi
                if [[ "${PIHOLE_DNS_2}" == "${strInvalid}" ]]; then
                    PIHOLE_DNS_2=""
                fi
                # and continue the loop.
                DNSSettingsCorrect=False
            else
                dialog --no-shadow --no-collapse --keep-tite \
                    --backtitle "Specify Upstream DNS Provider(s)" \
                    --title "Upstream DNS Provider(s)" \
                    --yesno "Are these settings correct?\\n"$'\t'"DNS Server 1:"$'\t'"${PIHOLE_DNS_1}\\n"$'\t'"DNS Server 2:"$'\t'"${PIHOLE_DNS_2}" \
                    "${r}" "${c}" && result=0 || result=$?

                case ${result} in
                "${DIALOG_OK}")
                    DNSSettingsCorrect=True
                    ;;
                "${DIALOG_CANCEL}")
                    DNSSettingsCorrect=False
                    ;;
                "${DIALOG_ESC}")
                    printf "  %b Escape pressed, exiting installer at DNS Settings%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
                    exit 1
                    ;;
                esac
            fi
        done
    else
        # Save the old Internal Field Separator in a variable,
        OIFS=$IFS
        # and set the new one to newline
        IFS=$'\n'
        for DNSServer in ${DNS_SERVERS}; do
            DNSName="$(cut -d';' -f1 <<<"${DNSServer}")"
            if [[ "${DNSchoices}" == "${DNSName}" ]]; then
                PIHOLE_DNS_1="$(cut -d';' -f2 <<<"${DNSServer}")"
                PIHOLE_DNS_2="$(cut -d';' -f3 <<<"${DNSServer}")"
                break
            fi
        done
        # Restore the IFS to what it was
        IFS=${OIFS}
    fi

    # Display final selection
    local DNSIP=${PIHOLE_DNS_1}
    [[ -z ${PIHOLE_DNS_2} ]] || DNSIP+=", ${PIHOLE_DNS_2}"
    printf "  %b Using upstream DNS: %s (%s)\\n\\n" "${INFO}" "${DNSchoices}" "${DNSIP}"
}

is_valid_url() {
    local url="$1"
    if [[ "$url" =~ ^(http|https)://.*\.com(/.*)?$ ]]; then
        return 0
    else
        return 1
    fi
}

# A function to display a list of example blocklists for users to select
chooseBlocklists() {
    # Back up any existing adlist file, on the off chance that it exists. Useful in case of a reconfigure.
    local BlackListCorrect
    if [[ -f "${adlistFile}" ]]; then
        mv "${adlistFile}" "${adlistFile}.old"
    fi
    until [[ "${BlackListCorrect}" = True ]]; do
        strInvalid="Invalid"
        if [[ ! "${blackList}" ]]; then
            prePopulate=""
        else
            prePopulate="${blackList}"
        fi
        # Let user select (or not) blocklists
        blackListSelection=$(
            dialog --no-shadow --keep-tite --output-fd 1 \
                --cancel-label "Exit" \
                --backtitle "Blacklist Selection" \
                --inputbox "Enter the URL blacklist API server DNS MASTER.\
                    \\n\\nFor example, 'https://www.<localhost>:<port>/<uri>' \
                    \\n\\nIf no information is available, please contact the administrator." \
                "${r}" "${c}" "${blackList}")
        result=$?
        case ${result} in
            "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
            printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
            exit 1
            ;;
        esac
        # If check a valid URL
        if is_valid_url "${blackListSelection}"; then
            dialog --no-shadow --no-collapse --keep-tite \
                --backtitle "Blacklist Selection" \
                --title "Blacklist Selection" \
                --yesno "Are these settings correct?\\n"$'\t'"Blacklist URL:\\n"$'\t'"${blackListSelection}" \
                "${r}" "${c}" && result=0 || result=$?
            case ${result} in
            "${DIALOG_OK}")
                BlackListCorrect=True
                printf "  %b Installing URL blacklist API server DNS MASTER
  %b%b %s%b\\n" "${INFO}" "${INFO}" "${COL_LIGHT_GREEN}" "${blackListSelection}" "${COL_NC}"
            echo "${blackListSelection}" >> "${adlistFile}"
                ;;
            "${DIALOG_CANCEL}")
                BlackListCorrect=False
                ;;
            "${DIALOG_ESC}")
                printf "  %b Escape pressed, exiting installer at Blacklist Settings%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
                exit 1
                ;;
            esac
            
        else
            printf "  %b%b Invalid URL blacklist API server DNS MASTER%b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${COL_NC}"
            dialog --no-shadow --keep-tite \
                --title "Invalid URL" \
                --backtitle "Invalid URL" \
                --msgbox "\\nInvalid URL blacklist API server DNS MASTER.\
                    \\n\\nInvalid URL: ${blackListSelection} \
                    \\n\\nPlease try again." \
                "${r}" "${c}"
            # set the variables back to nothing,
            if [[ "${blackListSelection}" == "${strInvalid}" ]]; then
                blackListSelection=""
            fi
            # and continue the loop.
            BlackListCorrect=False

        fi

    done
        

    # Create an empty adList file with appropriate permissions.
    if [ ! -f "${adlistFile}" ]; then
        install -m 644 /dev/null "${adlistFile}"
    else
        chmod 644 "${adlistFile}"
    fi
}

main() {
    local str="Root user check"
    printf "\\n"
    if [[ "${EUID}" -eq 0 ]]; then
        # they are root and all is good
        printf "  %b %s\\n" "${TICK}" "${str}"
        # Show the Pi-hole logo so people know it's genuine since the logo and name are trademarked
        show_ascii_berry
        make_temporary_log
    else
        # Otherwise, they do not have enough privileges, so let the user know
        printf "  %b %s\\n" "${INFO}" "${str}"
        printf "  %b %bScript called with non-root privileges%b\\n" "${INFO}" "${COL_LIGHT_RED}" "${COL_NC}"
        printf "      The Pi-hole requires elevated privileges to install and run\\n"
        printf "      Please check the installer for any concerns regarding this requirement\\n"
        printf "      Make sure to download this script from a trusted source\\n\\n"
        printf "  %b Sudo utility check" "${INFO}"

        # If the sudo command exists, try rerunning as admin
        if is_command sudo; then
            printf "%b  %b Sudo utility check\\n" "${OVER}" "${TICK}"

            # when run via curl piping
            if [[ "$0" == "bash" ]]; then
                # Download the install script and run it with admin rights
                exec curl -sSL https://raw.githubusercontent.com/pi-hole/pi-hole/master/automated%20install/basic-install.sh | sudo bash "$@"
            else
                # when run via calling local bash script
                exec sudo bash "$0" "$@"
            fi

            exit $?
        else
            # Otherwise, tell the user they need to run the script as root, and bail
            printf "%b  %b Sudo utility check\\n" "${OVER}" "${CROSS}"
            printf "  %b Sudo is needed for the Web Interface to run pihole commands\\n\\n" "${INFO}"
            printf "  %b %bPlease re-run this installer as root${COL_NC}\\n" "${INFO}" "${COL_LIGHT_RED}"
            exit 1
        fi
    fi

    # Check if SELinux is Enforcing and exit before doing anything else
    checkSelinux

    # Check for supported package managers so that we may install dependencies
    package_manager_detect

    # Notify user of package availability
    notify_package_updates_available
    printf "  %b Checking for / installing Required dependencies for OS Check...\\n" "${INFO}"
    install_dependent_packages "${OS_CHECK_DEPS[@]}"
    # Check that the installed OS is officially supported - display warning if not
    os_check

    # Install packages used by this installation script
    printf "  %b Checking for / installing Required dependencies for this install script...\\n" "${INFO}"
    install_dependent_packages "${INSTALLER_DEPS[@]}"
    # If the setup variable file exists,
    if [[ -f "${setupVars}" ]]; then
        # if it's running unattended,
        if [[ "${runUnattended}" == true ]]; then
            printf "  %b Performing unattended setup, no dialogs will be displayed\\n" "${INFO}"
            # Use the setup variables
            useUpdateVars=true
            # also disable debconf-apt-progress dialogs
            export DEBIAN_FRONTEND="noninteractive"
        else
            # If running attended, show the available options (repair/reconfigure)
            update_dialogs
        fi
    fi

    if [[ "${useUpdateVars}" == false ]]; then
        welcomeDialogs
        # Create directory for Pi-hole storage
        install -d -m 755 /etc/pihole/
        # Determine available interfaces
        get_available_interfaces
        # Find interfaces and let the user choose one
        chooseInterface
        # find IPv4 and IPv6 information of the device
        collect_v4andv6_information
        # Decide what upstream DNS Servers to use
        setDNS
        # Give the user a choice of blocklists to include in their install. Or not.
        chooseBlocklists
    else
        echo "zzzz"

    fi

}

if [[ "${SKIP_INSTALL}" != true ]]; then
    main "$@"
fi
