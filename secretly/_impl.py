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


class PinentryNotFound(Exception):
    """
    Raised when a C{pinentry} program does not exist.
    """


@attr.s(frozen=True)
class Pinentry(object):
    """
    A C{pinentry} that can prompt you for a password.

    @ivar _name: The name of the C{pinentry} program.  Must be in C{PATH}
        or an absolute path to an executable.
    @type _name: L{str}

    @ivar _argumentFactory: A callable that accepts no arguments and
        returns C{argv[1:]}.  Can raise L{PinentryNotFound} or
        L{OSError} to cause this C{pinentry} to be ignored.
    @type _argumentFactory: L{callable}
    """
    _name = attr.ib()
    _argumentFactory = attr.ib(default=lambda: [])

    def argv(self, _which=which):
        """
        Return an argv list suitable for passing to
        L{ProcessEndpoint}.

        @return: An argv L{list} suitable for passing to
            L{ProcessEndpoint}

        @raises: L{PinentryNotFound} if the requested pinentry program
        """
        argv = _which(self._name)[:1]
        if not argv:
            raise PinentryNotFound(self._name)
        argv.extend(self._argumentFactory())
        return argv


def ttynameArgument(
        _stdout=sys.stdout.fileno(),
):
    """
    C{pinentry-curses} requires C{--ttyname} be set to the process'
    controlling terminal so it can draw its dialogs.  This function
    either returns a list that sets C{--ttyname} to the terminal that
    underlies the calling process' stdout or raises L{OSError} if
    stdout has no terminal.
    """
    return ['--ttyname', os.ttyname(_stdout)]


PINENTRIES = (
    Pinentry('/usr/local/MacGPG2/libexec/pinentry-mac.app'
           '/Contents/MacOS/pinentry-mac'),
    Pinentry('pinentry-mac'),
    Pinentry('pinentry-curses', argumentFactory=ttynameArgument),
    Pinentry('pinentry'),
)


def choosePinentry(_pinentries=PINENTRIES):
    """
    Choose a C{pinentry} that can prompt you for a secret.

    @return: An argv list suitable for passing to L{ProcessEndpoint}

    @raises: L{RuntimeError} if no C{pinentry} is available.

    @see:
        U{https://www.gnupg.org/documentation/manuals/gnupg/Common-Problems.html}
    """
    for pinentry in _pinentries:
        try:
            return pinentry.argv()
        except (PinentryNotFound, OSError):
            continue
    else:
        raise RuntimeError(
            "Cannot find a pinentry to prompt you for a secret.")


@inlineCallbacks
def askForPassword(reactor, prompt, title, description, argv):
    """
    The documentation appears to be here only:
    https://github.com/gpg/pinentry/blob/287d40e879f767dbcb3d19b3629b872c08d39cf4/pinentry/pinentry.c#L1444-L1464

    TODO: multiple backends for password-prompting.
    """

    assuan = yield (ProcessEndpoint(reactor, argv[0], argv, os.environ.copy())
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
                                  .format(system=system, username=username),
                                  choosePinentry()))
        )
    yield maybeDeferred(action, secret)



if __name__ == '__main__':
    @react
    def main(reactor):
        return secretly(reactor, lambda pw: deferLater(reactor, 3.0, print,
                                                       'pw:', pw))
