""" Wrapper functions around navencrypt 3.10.1 commands """
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


if __name__ == "__main__":
    # Testing functions
    
