"""The Garden repl"""

import itertools
import shlex
import readline
import rlcompleter

from diff import ErrorType
from fanout import (
    fanout,
    unparsed_fanout,
)
from fuzz import fuzz
from grid import generate_grid, Grid
from http1 import HTTPRequest, HTTPResponse
from targets import SERVER_DICT, TRANSDUCER_DICT, Server


def print_request(r: HTTPRequest) -> None:
    print("    \x1b[0;34mHTTPRequest\x1b[0m(")  # Blue
    print(f"        method={r.method!r}, uri={r.uri!r}, version={r.version!r},")
    if len(r.headers) == 0:
        print("        headers=[],")
    else:
        print("        headers=[")
        for name, value in r.headers:
            print(f"            ({name!r}, {value!r}),")
        print("        ],")
    print(f"        body={r.body!r},")
    print("    ),")


def print_response(r: HTTPResponse) -> None:
    print(
        f"    \x1b[0;31mHTTPResponse\x1b[0m(version={r.version!r}, method={r.code!r}, reason={r.reason!r}),",  # Red
    )


def print_fanout(
    payload: list[bytes],
    servers: list[Server],
) -> None:
    for s, pts in zip(servers, fanout(payload, servers)):
        print(f"{s.name}: [")
        for r in pts:
            if isinstance(r, HTTPRequest):
                print_request(r)
            elif isinstance(r, HTTPResponse):
                print_response(r)
        print("]")


def print_unparsed_fanout(payload: list[bytes], servers: list[Server]) -> None:
    for server, result in zip(servers, unparsed_fanout(payload, servers)):
        print(f"\x1b[0;34m{server.name}\x1b[0m:")  # Blue
        for r in result:
            is_response: bool = r.startswith(b"HTTP/")
            if is_response:
                if len(r) > 80:
                    r = r[:80] + b"..."
                print("\x1b[0;31m", end="")  # Red
            print(repr(r) + "\x1b[0m")


def print_grid(grid: Grid, labels: list[str]) -> None:
    first_column_width: int = max(map(len, labels))
    labels = [label.ljust(first_column_width) for label in labels]

    # Vertical labels
    result: str = (
        "".join(
            f'{"".ljust(first_column_width - 1)}{" ".join(row)}\n'
            for row in itertools.zip_longest(
                *(s.strip().rjust(len(s)) for s in [" " * len(labels[0]), *labels]),
            )
        )
        + f"{''.ljust(first_column_width)}+{'-' * (len(labels) * 2 - 1)}\n"
    )

    # Horizontal labels; checks and exes.
    for label, row in zip(labels, grid):
        result += label.ljust(first_column_width) + "|"
        for entry in row:
            symbol: str
            if entry is None:
                symbol = " "
            elif entry in (ErrorType.OK, ErrorType.RESPONSE_DISCREPANCY):
                symbol = "\x1b[0;32m✓\x1b[0m"
            elif entry in (
                ErrorType.DISCREPANCY,
                ErrorType.REQUEST_DISCREPANCY,
                ErrorType.TYPE_DISCREPANCY,
                ErrorType.STREAM_DISCREPANCY,
            ):
                symbol = "\x1b[0;31mX\x1b[0m"
            elif entry in (ErrorType.INVALID,):
                symbol = "\x1b[37;41mX\x1b[0m"
            result += symbol + " "
        result += "\n"

    print(result, end="")


def print_stream(stream: list[bytes], id_no: int) -> None:
    print(f"[{id_no}]:", " ".join(repr(b)[1:] for b in stream))


def invalid_syntax() -> None:
    print("Invalid syntax.")


def is_valid_server_name(server_name: str) -> bool:
    if server_name not in SERVER_DICT:
        print(f"Server {server_name!r} not found")
        return False
    return True


def is_valid_transducer_name(transducer_name: str) -> bool:
    if transducer_name not in TRANSDUCER_DICT:
        print(f"Transducer {transducer_name!r} not found")
        return False
    return True


_INITIAL_PAYLOAD: list[bytes] = [b"GET / HTTP/1.1\r\nHost: whatever\r\n\r\n"]


def validate_server_names(server_names: list[str]) -> bool:
    for s in server_names:
        if not is_valid_server_name(s):
            print("Invalid server name: {s}")
            return False
    return True

def validate_transducer_names(transducer_names: list[str]) -> bool:
    for s in transducer_names:
        if not is_valid_transducer_name(s):
            print("Invalid transducer name: {s}")
            return False
    return True


# Tab completion setup
class GardenCompleter:
    def __init__(self):
        self.commands = [
            'payload', 'history', 'grid', 'fanout', 'unparsed_fanout', 'uf',
            'unparsed_transducer_fanout', 'utf', 'transduce', 't', 'help', 'servers', 'transducers', 'quit', 'exit'
        ]
        self.servers = list(SERVER_DICT.keys())
        self.transducers = list(TRANSDUCER_DICT.keys())
        
    def complete(self, text, state):
        """Return the next possible completion for 'text'."""
        if state == 0:
            # Parse the current line to understand context
            line = readline.get_line_buffer()
            tokens = line.split()
            
            if not tokens or (len(tokens) == 1 and not line.endswith(' ')):
                # Completing command name
                self.matches = [cmd for cmd in self.commands if cmd.startswith(text)]
            else:
                # Completing arguments based on command
                command = tokens[0]
                if command in ['grid', 'fanout', 'unparsed_fanout', 'uf']:
                    # Complete with server names
                    self.matches = [server for server in self.servers if server.startswith(text)]
                elif command in ['unparsed_transducer_fanout', 'utf', 'transduce', 't']:
                    # Complete with transducer names
                    self.matches = [trans for trans in self.transducers if trans.startswith(text)]
                else:
                    self.matches = []
        
        try:
            return self.matches[state]
        except IndexError:
            return None


def print_help():
    """Print comprehensive help information."""
    help_text = """
\x1b[1;32mHTTP Garden REPL Help\x1b[0m

\x1b[1;34mBasic Commands:\x1b[0m
  \x1b[0;36mhelp\x1b[0m                    Show this help message
  \x1b[0;36mservers\x1b[0m                 List all available servers
  \x1b[0;36mtransducers\x1b[0m             List all available transducers
  \x1b[0;36mquit\x1b[0m / \x1b[0;36mexit\x1b[0m             Exit the REPL

\x1b[1;34mPayload Management:\x1b[0m
  \x1b[0;36mpayload\x1b[0m                 Show current payload
  \x1b[0;36mpayload <data>\x1b[0m          Set new payload (can be multiple strings)
  \x1b[0;36mhistory\x1b[0m                 Show all payload history

\x1b[1;34mTesting Commands:\x1b[0m
  \x1b[0;36mgrid [servers...]\x1b[0m       Show compatibility grid for servers
  \x1b[0;36mfanout [servers...]\x1b[0m     Show parsed responses from servers
  \x1b[0;36munparsed_fanout [servers...]\x1b[0m  Show raw responses from servers
  \x1b[0;36muf [servers...]\x1b[0m         Alias for unparsed_fanout

\x1b[1;34mTransducer Commands:\x1b[0m
  \x1b[0;36munparsed_transducer_fanout [transducers...]\x1b[0m  Show raw responses from transducers
  \x1b[0;36mutf [transducers...]\x1b[0m    Alias for unparsed_transducer_fanout
  \x1b[0;36mtransduce <transducers...>\x1b[0m  Chain payload through transducers
  \x1b[0;36mt <transducers...>\x1b[0m      Alias for transduce

\x1b[1;34mExamples:\x1b[0m
  \x1b[0;33mpayload 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'\x1b[0m
    Set a basic GET request as payload

  \x1b[0;33mgrid nginx gunicorn hyper\x1b[0m
    Compare how nginx, gunicorn, and hyper handle the current payload

  \x1b[0;33mtransduce haproxy nginx_proxy\x1b[0m
    Send payload through HAProxy, then through Nginx proxy

  \x1b[0;33mfanout\x1b[0m
    Test current payload against all available servers

\x1b[1;34mNotes:\x1b[0m
  • Commands can be chained with semicolons: \x1b[0;33mpayload 'GET /'; grid\x1b[0m
  • Use quotes for payloads with spaces or special characters
  • Use \\r\\n for HTTP line endings in payloads
  • Tab completion is available for commands and server/transducer names
  • Press Ctrl+C to cancel current input, Ctrl+D to exit
"""
    print(help_text)


def print_servers():
    """Print all available servers."""
    print("\x1b[1;34mAvailable Servers:\x1b[0m")
    servers = sorted(SERVER_DICT.keys())
    for i, server in enumerate(servers):
        if i % 4 == 0:
            print()
        print(f"  \x1b[0;36m{server:<20}\x1b[0m", end="")
    print("\n")


def print_transducers():
    """Print all available transducers."""
    print("\x1b[1;34mAvailable Transducers:\x1b[0m")
    transducers = sorted(TRANSDUCER_DICT.keys())
    for i, transducer in enumerate(transducers):
        if i % 4 == 0:
            print()
        print(f"  \x1b[0;36m{transducer:<20}\x1b[0m", end="")
    print("\n")



def main() -> None:
    # Set up tab completion
    completer = GardenCompleter()
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    
    # Enable history
    readline.set_history_length(1000)
    
    print("\x1b[1;32mWelcome to the HTTP Garden REPL!\x1b[0m")
    print("Type '\x1b[0;36mhelp\x1b[0m' for available commands, or use tab completion.")
    print()
    
    payload_history: list[list[bytes]] = [_INITIAL_PAYLOAD]
    while True:
        try:
            line: str = input("\x1b[0;32mgarden>\x1b[0m ")  # Green
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            continue

        try:
            tokens: list[str] = [
                t[1:-1] if t[0] == t[-1] and t[0] in "\"'" else t
                for t in shlex.shlex(line)
            ]
        except ValueError:
            print("Couldn't lex the line! Are your quotes matched?")
            continue

        commands: list[list[str]] = []
        while ";" in tokens:
            commands.append(tokens[: tokens.index(";")])
            tokens = tokens[tokens.index(";") + 1 :]
        commands.append(tokens)

        for command in commands:
            payload: list[bytes] = payload_history[-1]
            match command:
                case []:
                    pass
                case ["payload"]:
                    print_stream(payload, len(payload_history) - 1)
                case ["payload", *symbols]:
                    try:
                        payload_history.append(
                            [
                                s.encode("latin1")
                                .decode("unicode-escape")
                                .encode("latin1")
                                for s in symbols
                            ],
                        )
                    except UnicodeEncodeError:
                        print(
                            "Couldn't encode the payload to latin1. If you're using multibyte characters, please use escape sequences (e.g. `\\xff`) instead.",
                        )
                    except UnicodeDecodeError:
                        print(
                            "Couldn't Unicode escape the payload. Did you forget to quote it?"
                        )
                case ["history"]:
                    for i, p in enumerate(payload_history):
                        print_stream(p, i)
                case ["grid", *symbols]:
                    if len(symbols) == 0:
                        symbols = list(SERVER_DICT.keys())
                    if validate_server_names(symbols):
                        print_grid(
                            generate_grid(payload, [SERVER_DICT[s] for s in symbols]),
                            symbols,
                        )
                case ["fanout", *symbols]:
                    if len(symbols) == 0:
                        symbols = list(SERVER_DICT.keys())
                    if validate_server_names(symbols):
                        print_fanout(payload, [SERVER_DICT[s] for s in symbols])
                case ["unparsed_fanout" | "uf", *symbols]:
                    if len(symbols) == 0:
                        symbols = list(TRANSDUCER_DICT.keys())
                    if validate_server_names(symbols):
                        print_unparsed_fanout(payload, [TRANSDUCER_DICT[s] for s in symbols])
                case ["unparsed_transducer_fanout" | "utf", *symbols]:
                    if len(symbols) == 0:
                        symbols = list(TRANSDUCER_DICT.keys())
                    if validate_transducer_names(symbols):
                        print_unparsed_fanout(
                            payload, [TRANSDUCER_DICT[s] for s in symbols]
                        )
                case ["transduce" | "t", *symbols]:
                    if validate_transducer_names(symbols):
                        transducers = [
                            TRANSDUCER_DICT[t_name] for t_name in symbols
                        ]
                        tmp: list[bytes] = payload
                        for transducer in transducers:
                            print_stream(tmp, len(payload_history) - 1)
                            try:
                                tmp = transducer.transduce(tmp)
                            except ValueError as e:
                                print(e)
                                break
                            if len(tmp) == 0:
                                print(f"{transducer.name} didn't respond")
                                break
                            print(f"    ⬇️ \x1b[0;34m{transducer.name}\x1b[0m")  # Blue
                            payload_history.append(tmp)
                        else:
                            print_stream(tmp, len(payload_history) - 1)
                case ["help"]:
                    print_help()
                case ["servers"]:
                    print_servers()
                case ["transducers"]:
                    print_transducers()
                case ["quit"] | ["exit"]:
                    print("Goodbye!")
                    return
                case _:
                    invalid_syntax()


if __name__ == "__main__":
    main()
