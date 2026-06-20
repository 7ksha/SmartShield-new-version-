from smartshield_files.common.smartshield_utils import utils
import os


def _chain_exists() -> bool:
    """
    Check if the smartshieldBlocking chain exists
    :return: True if it exists, False otherwise
    """
    sudo = utils.get_sudo_according_to_env()
    # check if smartshieldBlocking chain exists before flushing it and suppress
    # stderr and stdout while checking
    # 0 means it exists
    return (
        os.system(f"{sudo} iptables -nvL smartshieldBlocking >/dev/null 2>&1") == 0
    )


def del_smartshield_blocking_chain() -> bool:
    """Flushes and deletes everything in smartshieldBlocking chain"""
    if not _chain_exists():
        return False

    sudo = utils.get_sudo_according_to_env()

    # Delete all references to smartshieldBlocking inserted in INPUT OUTPUT
    # and FORWARD before deleting the chain
    cmd = (
        f"{sudo} iptables -D INPUT -j smartshieldBlocking >/dev/null 2>&1 ;"
        f" {sudo} iptables -D OUTPUT -j smartshieldBlocking >/dev/null 2>&1 ; "
        f"{sudo} iptables -D FORWARD -j smartshieldBlocking >/dev/null 2>&1"
    )
    os.system(cmd)

    # flush and delete all the rules in smartshieldBlocking
    cmd = (
        f"{sudo} iptables -F smartshieldBlocking >/dev/null 2>&1 ; "
        f"{sudo} iptables -X smartshieldBlocking >/dev/null 2>&1"
    )
    os.system(cmd)

    print("Successfully deleted smartshieldBlocking chain.")
    return True
