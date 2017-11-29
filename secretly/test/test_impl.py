import attr
import attr.validators
import os

import sys
from twisted.trial import unittest

from .. import _impl


class PinentryTests(unittest.SynchronousTestCase):
    """
    Tests for L{_impl.Pinentry}.
    """

    def setUp(self):
        self.pinentry = _impl.Pinentry(name="pinentry")

    def test_argvRaisesWhenNotFound(self):
        """
        Calling L{_impl.Pinentry.argv} raises
        L{_impl.PinentryNotFound} when the C{pinentry} does not exist.
        """
        self.assertRaises(
            _impl.PinentryNotFound,
            self.pinentry.argv,
            _which=lambda arg: [],
        )

    def test_argvReturnsListWhenFoundWithDefaultArgumentFactory(self):
        """
        Calling L{_impl.Pinentry.argv} returns a list containing the
        path to its C{pinentry} program with the default C{argumentFactory}.
        """
        path = ["/path/to/pinentry"]
        self.assertEqual(self.pinentry.argv(_which=lambda arg: path), path)

    def test_argvReturnsListWhenFoundWithCustomArgumentFactory(self):
        """
        Calling L{_impl.Pinentry.argv} returns a list containing the
        first available path to its C{pinentry} program and the
        arguments provided by the C{argumentFactory}.
        """
        def argumentFactory():
            return ["a", "b"]

        path = "/path/to/pin/entry"

        def which(arg):
            return [path, "ignored"]

        pinentry = _impl.Pinentry(
            name="pinentry",
            argumentFactory=argumentFactory
        )

        self.assertEqual(
            pinentry.argv(_which=which),
            [path] + argumentFactory(),
        )


class TTYNameArgumenIntegrationTests(unittest.SynchronousTestCase):
    """
    Integration tests for L{_impl.ttynameArgument}.

    These are integration tests because they exercise
    L{_impl.ttynameArgument}'s real implementation.
    """

    def test_stdoutNotTTY(self):
        """
        L{_impl.ttynameArgument} raises L{OSError} when stdout is not
        a tty.
        """
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)

        self.assertRaises(
            OSError,
            _impl.ttynameArgument,
            _stdout=write,
        )

    def test_ttyPathReturned(self):
        """
        The path to stdout's tty is returned as the argument to
        C{--ttyname}.
        """
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)

        argv = _impl.ttynameArgument(_stdout=master)

        self.assertEqual(len(argv), 2)

        argument, value = argv
        self.assertEqual("--ttyname", argument)

        with open(value, "rb") as tty:
            self.assertTrue(os.isatty(tty.fileno()))


@attr.s
class PinEntryArgvRaises(object):
    """
    An orchestrator for L{FakePinentry}s that causes its
    L{FakePinentry.argv} method to raise an exception.
    """
    _raises = attr.ib(attr.validators.instance_of(
        (_impl.PinentryNotFound, OSError)))

    def _argv(self):
        """
        Raise our exception.
        """
        raise self._raises


@attr.s
class PinEntryArgvReturns(object):
    """
    An orchestrator for L{FakePinentry}s that causes its
    L{FakePinentry.argv} method to return a value.
    """
    _returns = attr.ib()

    @_returns.validator
    def check(self, attribute, value):
        listOfStrs = isinstance(value, list) and all(
            isinstance(el, str) for el in value)
        if not listOfStrs:
            raise ValueError("Must be list of strings.")

    def _argv(self):
        """
        Raise our exception.

        @return: The L{list} passed to our initializer.
        """
        return self._returns


@attr.s
class FakePinentry(object):
    """
    A fake L{Pinentry}.
    """
    _orchestrator = attr.ib(validator=attr.validators.instance_of(
        (PinEntryArgvRaises, PinEntryArgvReturns)))

    def argv(self):
        """
        Delegates to our orchestrator's argv.

        @return: Whatever the orchestrator returns.
        """
        return self._orchestrator._argv()


class VerifyFakePinentryIntegrationTests(unittest.SynchronousTestCase):
    """
    Test that L{FakePinentry}'s behavior matches L{_impl.Pinentry}.

    These are integration tests because they exercise
    L{_impl.Pinentry}'s real implementation.
    """

    def test_pinentryNotFound(self):
        """
        L{FakePinentry.argv} simulates L{Pinentry.argv}'s behavior
        when a C{pinentry} is not found.
        """
        missing = "missing"
        fake = FakePinentry(
            PinEntryArgvRaises(_impl.PinentryNotFound(missing)))
        real = _impl.Pinentry(missing)

        fakeException = self.assertRaises(_impl.PinentryNotFound, fake.argv)

        self.patch(os, "environ", {})
        realException = self.assertRaises(_impl.PinentryNotFound, real.argv)

        self.assertEqual(str(fakeException), str(realException))

    def test_argumentFactoryRaisesOSError(self):
        """
        L{FakePinentry.argv} simulates L{Pinentry.argv}'s behavior
        when the argument factory raises L{OSError}.
        """
        error = OSError("failed", 11)
        fake = FakePinentry(PinEntryArgvRaises(error))

        def raisesOSError():
            raise error

        real = _impl.Pinentry(sys.executable, argumentFactory=raisesOSError)

        fakeException = self.assertRaises(OSError, fake.argv)
        realException = self.assertRaises(OSError, real.argv)

        self.assertEqual(str(fakeException), str(realException))

    def test_returnsList(self):
        """
        L{FakePinentry.argv} simulates L{Pinentry.argv} when the
        executable is found.
        """
        fake = FakePinentry(PinEntryArgvReturns([sys.executable]))
        real = _impl.Pinentry(sys.executable)
        self.assertEqual(fake.argv(), real.argv())

    def test_canOnlyReturnListOfStrings(self):
        """
        L{FakePinentry.argv} can only return a list of strings.
        """
        self.assertRaises(ValueError, PinEntryArgvReturns, 1)
        self.assertRaises(ValueError, PinEntryArgvReturns, [1])


class ChoosePinEntryTests(unittest.SynchronousTestCase):
    """
    Tests for L{_impl.choosePinentry}.
    """

    def test_noPinentriesFound(self):
        """
        L{RuntimeError} is raised if no C{pinentry} programs are
        found.
        """
        self.assertRaises(RuntimeError, _impl.choosePinentry, [])

    def test_skipPinentryNotFound(self):
        """
        L{PinEntry}s that whose L{PinEntry.argv} method raises
        L{PinentryNotFound} are skipped.
        """
        argv = ["argv0", "argv1"]
        pinentries = [
            FakePinentry(PinEntryArgvRaises(_impl.PinentryNotFound)),
            FakePinentry(PinEntryArgvReturns(argv)),
        ]

        self.assertEqual(_impl.choosePinentry(pinentries), argv)

    def test_skipOSError(self):
        """
        L{PinEntry}s that whose L{PinEntry.argv} method raises
        L{OSError} are skipped.
        """
        argv = ["argv0", "argv1"]
        pinentries = [
            FakePinentry(PinEntryArgvRaises(OSError)),
            FakePinentry(PinEntryArgvReturns(argv)),
        ]

        self.assertEqual(_impl.choosePinentry(pinentries), argv)

    def test_returnsFirstFound(self):
        """
        The first found L{PinEntry}s is returned.
        """
        argv = ["argv0", "argv1"]
        otherArgv = ["otherArgv0", "otherArgv1"]
        pinentries = [
            FakePinentry(PinEntryArgvReturns(argv)),
            FakePinentry(PinEntryArgvReturns(otherArgv)),
        ]

        self.assertEqual(_impl.choosePinentry(pinentries), argv)
