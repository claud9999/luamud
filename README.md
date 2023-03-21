# LuaMUD

## History

In my college days (around 1990) I worked heavily on the DaemonMUCK software codebase--DaemonMUCK was based on TinyMUCK (which, in turn, was based on TinyMUD) and had a FORTH-like internal language. In other words, players could write software inside the virtual environment that would interact with the environment; enabling items, rooms and the like to be dynamic and responsive rather than static.

DaemonMUCK added a number of features to TinyMUCK, particularly pre-emptive multitasking so that the FORTH code folks ran inside the MUD would be able to run continuously and safely. (For a comparison, LambdaMOO, one of the only other multitasking MUDs, was cooperative. If a task took too many cycles without yielding control, the MOO would terminate it.)

## Issues with DaemonMUCK

Beyond being code that hasn't been touched in probably 20 years, there were a number of design decisions that are contrary to modern sensibilities:

1. The object database lived in RAM. At the time that MUD servers were developed, storage systems were slow. Instead of managing all of the MUD data in a database or other file system structure, MUDs would load the entire server into RAM and occasionally write it back out. This would result in a lot of memory being used, the possibility of the "dump" being corrupted, and crashes of the server could result in lost data.

2. Security was in its infancy--A lot of DaemonMUCK (and, I suspect, a lot of other MUDs) do not perform memory operations in a secure manner (for example, there are a lot of "strcpy" and "sprintf" calls.) Clearly, exposing such software to the Internet of today is asking for the loss of the keys to the kingdom.

3. Confusing/complex feature set--beyond the complex history of TinyMUD and TinyMUCK, DaemonMUCK also (later) incorporated TinyMUSH concepts. While this would expand the capabilities and the familiarity to more players, it results in an overly-complex and poorly maintained codebase.

4. Single-process, single-thread--while generally this was not an issue as the FORTH language engine was reliable in ensuring activities would not tie up the process, this is not a scalable solution for more than tens-of-players simultaneously connected to the MUD.

## Design

The LuaMUD is designed from the ground-up using contemporary techniques and tools. CMake for build management, GIT for version control, Markdown for documentation.

### Lua

For the in-game programming language, LuaMUD will use Lua (obv.) for ease of programming, a well-featured language familiar with game developers, and for ongoing support of the language by the developers.

### Sqlite

Persistence of the LuaMUD will be in a SQLite database with a simplistic, genre-neutral, object datastore.

### Features

While Lua has cooperative multitasking (through continuations), support for pre-emptive multitasking requires a complex third-party library such as Lua Lanes. Instead I am proposing LuaMUD write its own multitasking architecture:

* Pthreads for multi-threading, each thread being dedicated to one Lua state of execution.
* Inter-thread communications via SQLite temporary table and a semaphore to signal data available.
* All SQLite interactions will be wrapped in functions to provide an object-oriented view of the system to Lua.
* Sandbox for Lua -- no network/file I/O, no loading of libraries, no direct access to SQLite, limited RAM + IO.
* Per-user resource quotas.
* Fine-grained object/property access permissions.
* TLS connectivity via OpenSSL.
* User authentication via TLS client cert, TOTP, user/pass.
* Support for a variety of clients (TinyFugue, web browser, SSH client, ???)
* Object-oriented capabilities: inheritance, class methods.
* Minimal "standard" properties.
* Simple in-game editing/tracing/debugging of Lua source.
* Minimal built-in game verbs.
* Data-at-rest cryptography? (Need to ensure admins can read/write encrypted data.)
* NO GNU Readline for command editing, autocompletion, and history.
* STC for strings/datatypes - https://github.com/tylov/STC

## TODO

* Lua memory tracking/limiting.
* Command-handling loop.
* Access control.
* Recursive query (?) for property retrieval.
* GNU Readline and OpenSSL seem incompatible; GNU Readline needs a `FILE *` for input and output. OpenSSL requires calls to `SSL_read()` and `SSL_write()`. Any (reasonable) way around this?
* Move SHA1 to BIO?
