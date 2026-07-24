# SPDX-License-Identifier: Apache-2.0
"""Single ``passwolf`` console entry point dispatching to the change, reset, and policy subcommands.

The package ships one command, ``passwolf``, with three subcommands that map one-to-one to the
operations the codebase keeps deliberately separate: ``change`` proves the account's current secret
and needs no privilege, ``reset`` is a privileged overwrite that proves nothing, and ``policy`` reads
the effective password policy without ever touching a secret. Each subcommand owns its own argument
parser (in change.py, reset.py, and pwpolicy.py); this module only routes ``passwolf <command> ...``
to the matching entry point, so the three never share or leak flags into one another.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from . import __version__
from .change import main as change_main
from .pwpolicy import main as policy_main
from .reset import main as reset_main

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# Subcommand name -> entry point. The names use the operation vocabulary (change / reset / policy)
# shared across the package rather than the module file names, so the CLI surface stays stable even
# if a module is renamed.
_COMMANDS: dict[str, Callable[[list[str] | None], int]] = {
    "change": change_main,
    "reset": reset_main,
    "policy": policy_main,
}

_USAGE = """usage: passwolf <command> [options]

commands:
  change   change a password or hash by proving the account's current secret (no privilege)
  reset    reset a password or hash as a privileged caller (proves nothing about the old secret)
  policy   read the effective password and lockout policy

Run 'passwolf <command> --help' for the options of a given command.
"""


def main(argv: Sequence[str] | None = None) -> int:
    """Route ``passwolf <command> ...`` to the matching subcommand entry point."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(_USAGE, end="")
        return 0
    if args[0] in {"-V", "--version"}:
        print(f"passwolf {__version__}")
        return 0
    handler = _COMMANDS.get(args[0])
    if handler is None:
        print(f"passwolf: unknown command {args[0]!r}\n", file=sys.stderr)
        print(_USAGE, end="", file=sys.stderr)
        return 2
    # The subcommand's own parser (prog="passwolf <command>") consumes the remaining argv.
    return handler(args[1:])


if __name__ == "__main__":
    sys.exit(main())
