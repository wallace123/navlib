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
import sys
import pexpect


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


def nav_prepare_loop(passwd, lfile, device, directory, logfile=sys.stdout):
    """ Prepares the encrypted volume backed by a loop device
        passwd - Navencrypt password
        lfile - File to use for loop device
        device - loop device (i.e. /dev/loop0
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
    index = child.expect(opts)

    child.close()

    # Relying on navencrypt-prepare exit status to indicate success
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

    return index == 0


if __name__ == "__main__":
    # Testing functions

    if nav_encrypt('thisisatestpassword', '@docker1-mount',
                   '/dmcrypt/lib/docker1', '/docker1-mount'):
        print "nav_encrypt succeeded"
    else:
        print "nav_encrypt failed"
