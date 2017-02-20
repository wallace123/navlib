""" Wrapper functions around navencrypt 3.10.1 commands """
import sys
import pexpect


def nav_register(passwd, kts, port, auth, orgname, clientname):
    """ Register navencrypt host with the Key Trustee Server. Suports single passphrase only.
        passwd - Navencrypt password to set
        kts - Key Trustee Server IP/hostname
        port - Port Key Trustee Server is listening on
        auth - Auth Secret on the Key Trustee Server
        orgname - Organization Name set on the Key Trustee Server
        clientname - Name for this Navencrypt client node
    """
    cmd = 'navencrypt register --server=%s:%s --org=%s --auth=%s --clientname=%s '\
          '--skip-ssl-check' % (kts, port, orgname, auth, clientname)
    child = pexpect.spawn(cmd)
    opts = ['Choose MASTER key type:', "Try `navencrypt register --help' for more information."]
    index = child.expect(opts)

    if index == 0:
        child.sendline('1')
        child.expect('Type MASTER passphrase:')
        child.sendline(passwd)
        child.expect('Verify MASTER passphrase:')
        child.sendline(passwd)

        opts = ['navencrypt is now registered.', 'ERROR:']
        index = child.expect(opts)

        # Returns True if Navencrypt registered successfully
        return index == 0
    else:
        # If we're here, command line was incorrect
        return False


def nav_prepare_loop(passwd, lfile, device, directory, logfile=sys.stdout):
    """ Prepares the encrypted volume backed by a loop device
        passwd - Navencrypt password
        lfile - File to use for loop device
        device - loop device (i.e. /dev/loop0
        directory - Encrypted directory mount point
        logfile - print output to logfile
    """
    cmd = 'navencrypt-prepare -d %s %s %s' % (lfile, device, directory)

    child = pexpect.spawn(cmd)
    child.logfile_read = logfile

    opts = ['Type MASTER passphrase', pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    if index == 0:
        child.sendline(passwd)
    else:
        print 'ERROR'
        return False

    opts = [pexpect.EOF, pexpect.TIMEOUT]
    index = child.expect(opts)

    child.close()

    # Relying on navencrypt-prepare exit status to indicate success
    # Check logs if this succeeds but things don't seem right
    return child.exitstatus == 0


if __name__ == "__main__":
    # Testing functions
    if nav_prepare_loop('thisisatestpassword', '/dmcrypt/docker1-loop',
                        '/dev/loop0', '/docker1-mount'):
        print "nav_prepare_loop succeeded"
    else:
        print "nav_prepare_loop failed"
