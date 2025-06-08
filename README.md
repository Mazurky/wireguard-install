# WireGuard Install with Whiptail GUI

This is a fork of the [angristan/wireguard-install](https://github.com/angristan/wireguard-install) script that adds a CLI-based graphical interface using [Whiptail](https://en.wikibooks.org/wiki/Bash_Shell_Scripting/Whiptail) for an improved user experience. If Whiptail is not available on the system, the script gracefully falls back to the original standard prompts.

This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Installation & Usage

1. **Download the script**:

   ```bash
   curl -O https://raw.githubusercontent.com/mazurky/wireguard-install/master/wireguard-install.sh
   # or
   wget https://raw.githubusercontent.com/mazurky/wireguard-install/master/wireguard-install.sh
   ```

2. **Make it executable**:

   ```bash
   chmod +x wireguard-install.sh
   ```

3. **Run as root**:

   ```bash
   sudo ./wireguard-install.sh
   ```

4. **Follow the dialogs**:

   * Use the Whiptail GUI (or CLI prompts) to install WireGuard, add or revoke clients, and configure your VPN.
   * Rerun the script anytime to manage clients or uninstall.

## Credits

* Original script by [angristan](https://github.com/angristan/wireguard-install).
* This fork adds Whiptail UI enhancements and colored output.
