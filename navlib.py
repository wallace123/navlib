""" Wrapper functions around navencrypt 3.10.1 commands. Uses pexpect to handle entering
of navencrypt admin password (only supports single-passphrase at the moment).

Tips with pexpect:
  - End of line is \r\n for terminals
  - Two pexpect exceptions are EOF and TIMEOUT. Add to expect opts list if you want
    to avoid try/except blocks for code size saving.
  - You can just expect EOF if you want to wait for all output of a child to finish.
    All output will be in child.before.
  - Default logfile is stdout. You can open a separate file and pass to functions
    to log output to a file.
  - Have to call child.close() to get exitstatus.
"""
import os
import sys
import time
import pexpect


# pylint: disable=R0913
def nav_register(passwd, kts, port, auth, orgname, clientname, logfile=sys.stdout):
    """ Register navencrypt host with the Key Trustee Server. Suports single passphrase only.
        passwd - Navencrypt password to set
        kts - Key Trustee Server IP/hostname
        port - Port Key Trustee Server is listening on
        auth - Auth Secret on the Key Trustee Server
        orgname - Organization Name set on the Key Trustee Server
        clientname - Name for this Navencrypt client node
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt register --server=%s:%s --org=%s --auth=%s --clientname=%s '\
          '--skip-ssl-check' % (kts, port, orgname, auth, clientname)

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Choose MASTER key type:', "Try `navencrypt register --help' for more information.",
            pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline('1')
        child.expect('Type MASTER passphrase:')
        child.sendline(passwd)
        child.expect('Verify MASTER passphrase:')
        child.sendline(passwd)

        opts = ['navencrypt is now registered.', 'ERROR:', pexpect.EOF, pexpect.TIMEOUT]
        index = child.expect(opts)

        # Returns True if Navencrypt registered successfully
        return index == 0
    else:
        # If we're here, something went wrong, check logfile
        return False


def check_nav_password(passwd, logfile=sys.stdout):
    """ Checks that the password given is the navencrypt password """
    cmd = 'navencrypt acl --list'

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = ['You typed an incorrect key', '== Passphrase must be between 15',
            pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0 or index == 1:
        # Incorrect password
        return False
    else:
        # Password correct
        return True


def nav_prepare_loop(passwd, lfile, device, directory, logfile=sys.stdout):
    """ Prepares the encrypted volume backed by a loop device
        passwd - Navencrypt password
        lfile - File to use for loop device
        device - loop device (i.e. /dev/loop0)
        directory - Encrypted directory mount point
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt-prepare -d %s %s %s' % (lfile, device, directory)

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = [pexpect.EOF, pexpect.TIMEOUT]
    child.expect(opts)

    child.close()

    # Relying on navencrypt-prepare exit status to indicate success.
    # Doing this because this command does a lot of setup and need to
    # ensure all the prep succeeds.
    # Check logs if this succeeds but things don't seem right
    return child.exitstatus == 0


def nav_prepare_loop_del(passwd, device, logfile=sys.stdout):
    """ Does a navencrypt-prepare -f <device> which forces undo of prepare
        passwd - Navencrypt password
        device - block device (i.e. /dev/loop0)
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt-prepare -f %s' % device

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['WARNING:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline('yes')
    else:
        return False

    opts = ['Are you sure to continue', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline('yes')
    else:
        return False

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = [pexpect.EOF, pexpect.TIMEOUT]
    child.expect(opts)

    child.close()

    # Relying on navencrypt-prepare exit status to indicate success.
    # Doing this because this command does multiple commands and need
    # to ensure all the commands succeed.
    # Check logs if this succeeds but things don't seem right
    return child.exitstatus == 0


def nav_encrypt(passwd, category, directory, mount, logfile=sys.stdout):
    """ Move directory to navencrypt encrypted mount point
        passwd - Navencrypt password
        category - Name where to copy files within navencrypt mounted directories
        directory - directory to encrypt
        mount - navencrypt mounted directory
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt-move encrypt %s %s %s' % (category, directory, mount)

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = ['Done.', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)
    child.close()

    if child.exitstatus == 0:
        # navencrypt-move is exiting but keeping lock file.
        # delete lock file so we can run the move command again.
        time.sleep(1)
        if os.path.isfile('/var/run/navencrypt-move.lock'):
            os.remove('/var/run/navencrypt-move.lock')
    else:
        return False

    return index == 0


def nav_acl_add(passwd, rule, logfile=sys.stdout):
    """ Sets an ACL rule for the navencrypt mounted directory
        passwd - Navencrypt password
        rule - The ACL rule to set (see documentation for valid rules)
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt acl --add --rule="%s"' % rule

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    # pylint: disable=W1401
    opts = ['1 rule\(s\) were added', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)
    child.close()

    return index == 0


def nav_acl_del(passwd, rule, logfile=sys.stdout):
    """ Deletes an ACL rule for the navencrypt mounted directory
        passwd - Navencrypt password
        rule - The ACL rule to search for from navencrypt acl --list
        logfile - print pexpect output to logfile
    """
    # First have to get the rule number before deleting
    cmd = 'navencrypt acl --list'

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = [pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        output = child.before
        rule_list = output.split('\r\n')
        # Delete the first two items so list only contains rules
        del rule_list[0:2]
        # Delete the last item which is empty
        del rule_list[-1]

        # Parses through rule output to get the rule number
        rule_num = 0
        for aclrule in rule_list:
            rule_items = aclrule.split()
            match = ''
            for item in rule_items[1:]:
                match += item + ' '
            if rule + ' ' == match:
                rule_num = rule_items[0]

        # Now ready to delete rule
        cmd = 'navencrypt acl --del -n %s' % rule_num

        child = pexpect.spawn(cmd)
        child.logfile_read = logfile

        opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
        index = child.expect(opts)

        if index == 0:
            child.sendline(passwd)
        else:
            return False

        # pylint: disable=W1401
        opts = ['1 rule\(s\) were deleted', pexpect.EOF, pexpect.TIMEOUT]
        index = child.expect(opts)
        child.close()

        return index == 0
    else:
        return False


def nav_set_mode(passwd, mode, logfile=sys.stdout):
    """ Sets the mode (permissive or enforcing) for navencrypt
        passwd - Navencrypt password
        mode - enforcing or permissive
        logfile - print pexpect output to logfile
    """
    cmd = 'navencrypt set --mode=%s' % mode

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase:', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        return False

    opts = ['%s mode set' % mode, pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)
    child.close()

    return index == 0


if __name__ == "__main__":
    # Testing functions
    pass
