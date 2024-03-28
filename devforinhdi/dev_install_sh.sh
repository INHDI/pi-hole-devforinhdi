#!/usr/bin/env bash
set -e
export PATH+=':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

coltable="/opt/pihole/COL_TABLE"

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
    if [ "$PIHOLE_SKIP_OS_CHECK" != true ]; then
        # This function gets a list of supported OS versions from a TXT record at versions.pi-hole.net
        # and determines whether or not the script is running on one of those systems
        local remote_os_domain valid_os valid_version valid_response detected_os detected_version display_warning cmdResult digReturnCode response
        remote_os_domain=${OS_CHECK_DOMAIN_NAME:-"versions.pi-hole.net"}

        detected_os=$(grep '^ID=' /etc/os-release | cut -d '=' -f2 | tr -d '"')
        detected_version=$(grep VERSION_ID /etc/os-release | cut -d '=' -f2 | tr -d '"')
        cmdResult="$(dig +short -t txt "${remote_os_domain}" @ns1.pi-hole.net 2>&1; echo $?)"
        printf "  %b Supported OS detected\\n" "${cmdResult}"
        # Gets the return code of the previous command (last line)
        digReturnCode="${cmdResult##*$'\n'}"

        if [ ! "${digReturnCode}" == "0" ]; then
            valid_response=false
        else
            # Dig returned 0 (success), so get the actual response, and loop through it to determine if the detected variables above are valid
            response="${cmdResult%%$'\n'*}"
            # If the value of ${response} is a single 0, then this is the return code, not an actual response.
            if [ "${response}" == 0 ]; then
                valid_response=false
            fi

            IFS=" " read -r -a supportedOS < <(echo "${response}" | tr -d '"')
            for distro_and_versions in "${supportedOS[@]}"; do
                distro_part="${distro_and_versions%%=*}"
                versions_part="${distro_and_versions##*=}"

                # If the distro part is a (case-insensitive) substring of the computer OS
                if [[ "${detected_os^^}" =~ ${distro_part^^} ]]; then
                    valid_os=true
                    IFS="," read -r -a supportedVer <<<"${versions_part}"
                    for version in "${supportedVer[@]}"; do
                        if [[ "${detected_version}" =~ $version ]]; then
                            valid_version=true
                            break
                        fi
                    done
                    break
                fi
            done
        fi

        if [ "$valid_os" = true ] && [ "$valid_version" = true ] && [ ! "$valid_response" = false ]; then
            display_warning=false
        fi

        if [ "$display_warning" != false ]; then
            if [ "$valid_response" = false ]; then

                if [ "${digReturnCode}" -eq 0 ]; then
                    errStr="dig succeeded, but response was blank. Please contact support"
                else
                    errStr="dig failed with return code ${digReturnCode}"
                fi
                printf "  %b %bRetrieval of supported OS list failed. %s. %b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${errStr}" "${COL_NC}"
                printf "      %bUnable to determine if the detected OS (%s %s) is supported%b\\n" "${COL_LIGHT_RED}" "${detected_os^}" "${detected_version}" "${COL_NC}"
                printf "      Possible causes for this include:\\n"
                printf "        - Firewall blocking certain DNS lookups from Pi-hole device\\n"
                printf "        - ns1.pi-hole.net being blocked (required to obtain TXT record from versions.pi-hole.net containing supported operating systems)\\n"
                printf "        - Other internet connectivity issues\\n"
            else
                printf "  %b %bUnsupported OS detected: %s %s%b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${detected_os^}" "${detected_version}" "${COL_NC}"
                printf "      If you are seeing this message and you do have a supported OS, please contact support.\\n"
            fi
            printf "\\n"
            printf "      %bhttps://docs.pi-hole.net/main/prerequisites/#supported-operating-systems%b\\n" "${COL_LIGHT_GREEN}" "${COL_NC}"
            printf "\\n"
            printf "      If you wish to attempt to continue anyway, you can try one of the following commands to skip this check:\\n"
            printf "\\n"
            printf "      e.g: If you are seeing this message on a fresh install, you can run:\\n"
            printf "             %bcurl -sSL https://install.pi-hole.net | sudo PIHOLE_SKIP_OS_CHECK=true bash%b\\n" "${COL_LIGHT_GREEN}" "${COL_NC}"
            printf "\\n"
            printf "           If you are seeing this message after having run pihole -up:\\n"
            printf "             %bsudo PIHOLE_SKIP_OS_CHECK=true pihole -r%b\\n" "${COL_LIGHT_GREEN}" "${COL_NC}"
            printf "           (In this case, your previous run of pihole -up will have already updated the local repository)\\n"
            printf "\\n"
            printf "      It is possible that the installation will still fail at this stage due to an unsupported configuration.\\n"
            printf "      If that is the case, you can feel free to ask the community on Discourse with the %bCommunity Help%b category:\\n" "${COL_LIGHT_RED}" "${COL_NC}"
            printf "      %bhttps://discourse.pi-hole.net/c/bugs-problems-issues/community-help/%b\\n" "${COL_LIGHT_GREEN}" "${COL_NC}"
            printf "\\n"
            exit 1

        else
            printf "  %b %bSupported OS detected%b\\n" "${TICK}" "${COL_LIGHT_GREEN}" "${COL_NC}"
        fi
    else
        printf "  %b %bPIHOLE_SKIP_OS_CHECK env variable set to true - installer will continue%b\\n" "${INFO}" "${COL_LIGHT_GREEN}" "${COL_NC}"
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

}

if [[ "${SKIP_INSTALL}" != true ]]; then
    main "$@"
fi
