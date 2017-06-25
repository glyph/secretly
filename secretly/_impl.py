
from __future__ import unicode_literals, print_function

import os
import sys

import attr

import keyring

from twisted.python.procutils import which

from twisted.protocols.basic import LineReceiver

from twisted.internet.defer import (
    Deferred, maybeDeferred, inlineCallbacks, returnValue)
from twisted.internet.endpoints import ProcessEndpoint
from twisted.internet.protocol import Factory
from twisted.internet.task import react, deferLater


@attr.s
class AssuanResponse(object):
    """
    Record encapsulating a response from pinentry.
    """
    data = attr.ib()
    debugInfo = attr.ib()



class AssuanError(Exception):
    """
    Record encapsulating a problem from pinentry (probably: the user hit
    'cancel').
    """



class SimpleAssuan(LineReceiver, object):
    """
    Simple Assuan protocol speaker.
    """
    delimiter = b'\n'

    def __init__(self):
        self._ready = False
        self._dq = []
        self._bufferedData = []

    def connectionMade(self):
        """
        Connection established; work around
        https://twistedmatrix.com/trac/ticket/6606 gfdi.
        """
        self.transport.disconnecting = False

    def issueCommand(self, command, *args):
        """
        Issue the given Assuan command and return a Deferred that will fire
        with the response.
        """
        result = Deferred()
        self._dq.append(result)
        self.sendLine(b" ".join([command] + list(args)))
        return result


    def _currentResponse(self, debugInfo):
        """
        Pull the current response off the queue.
        """
        bd = b''.join(self._bufferedData)
        self._bufferedData = []
        return AssuanResponse(bd, debugInfo)


    def lineReceived(self, line):
        """
        A line was received.
        """
        if line.startswith(b"#"): # ignore it
            return
        if line.startswith(b"OK"):
            # if no command issued, then just 'ready'
            if self._ready:
                self._dq.pop(0).callback(self._currentResponse(line))
            else:
                self._ready = True
        if line.startswith(b"D "):
            self._bufferedData.append(line[2:].replace(b"%0A", b"\r")
                                      .replace(b"%0D", b"\n")
                                      .replace(b"%25", b"%"))
        if line.startswith(b"ERR"):
            self._dq.pop(0).errback(AssuanError(line))


@inlineCallbacks
def askForPassword(reactor, prompt, title, description):
    """
    The documentation appears to be here only:
    https://github.com/gpg/pinentry/blob/287d40e879f767dbcb3d19b3629b872c08d39cf4/pinentry/pinentry.c#L1444-L1464

    TODO: multiple backends for password-prompting.
    """
    executable = (
        # It would be nice if there were a more general mechanism for this...
        which('/usr/local/MacGPG2/libexec/pinentry-mac.app'
              '/Contents/MacOS/pinentry-mac') +
        which('pinentry-mac') +
        which('pinentry')
    )[0]
    argv = [executable]
    assuan = yield (ProcessEndpoint(reactor, executable, argv,
                                    os.environ.copy())
                    .connect(Factory.forProtocol(SimpleAssuan)))
    try:
        yield assuan.issueCommand(b"SETPROMPT", prompt.encode("utf-8"))
        yield assuan.issueCommand(b"SETTITLE", title.encode("utf-8"))
        yield assuan.issueCommand(b"SETDESC", description.encode("utf-8"))
        response = yield assuan.issueCommand(b"GETPIN")
    finally:
        assuan.issueCommand(b"BYE")
    returnValue(response.data.decode("utf-8"))



@inlineCallbacks
def secretly(reactor, action, system=None, username=None,
                    prompt="Password:"):
    """
    Call the given C{action} with a secret value.

    @return: a L{Deferred} that fires with C{action}'s result, or
        L{NoSecretError} if no secret can be retrieved.
    """
    if system is None:
        system = action.__module__
        if system == '__main__':
            system = os.path.abspath(sys.argv[0])
    if username is None:
        from getpass import getuser
        username = getuser()
    while True:
        secret = keyring.get_password(system, username)
        if secret is not None:
            break
        keyring.set_password(
            system, username,
            (yield askForPassword(reactor, prompt, "Enter Password",
                                  "Password Prompt for {username}@{system}"
                                  .format(system=system, username=username)))
        )
    yield maybeDeferred(action, secret)



if __name__ == '__main__':
    @react
    def main(reactor):
        return secretly(reactor, lambda pw: deferLater(reactor, 3.0, print,
                                                       'pw:', pw))
