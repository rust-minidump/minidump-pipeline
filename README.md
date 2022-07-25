# minidump-pipeline

**(NOTHING TO SEE HERE, YET)**

This project attempts to be a whole-system pipeline demonstrating how to use 
the various minidump-based crash-reporting tools written in Rust, across the
entire development pipeline:

1. Build: Compile Your Project And Collect Symbols
2. Symbols: Host Your Symbols
3. Client: Crash On The Client And Send A Report
4. Processor: Receive A Report And Process It (With Symbols)
5. Reporter: Aggregate/Search/Display Processed Reports

Because there are 5 completely different environments and lots of configuration
you might want to do for each, the ecosystem is covered by various projects, even
though we're all kind of working together on this stuff.

> [Don't know what a minidump is? Check out our docs for some background][minidump-ours]!



# Fully Streamlined Workflow (Pay Someone Else)

Just use [sentry.io][]. 

Yeah uh, doing this all yourself is a ton of work, and you can just give people money
to deal with a lot of the details for you? A lot of the libraries in The Pipeline are
comaintained by them, and they use all this stuff in their own tooling, so, really
that is the easiest way to use this stuff.

I don't even work for them, I just wanted to be honest about the path of least resistance.
But ok let's dig into what to use if you want to do It All Yourself (or you know, work
for one of the companies that actually maintains these libraries/applications).



# Streamlined Workflow

The most streamlined summary of what to do is:

1. Build with [dump_syms][]
2. Host Your Symbols With ??? ("just" need a [static file server][tecken])
2. Deploy with [minidumper][]
3. Process with [minidump-stackwalk][]
4. Display with ??? (on your own... [minidump-debugger][]?)

Ok that's a bit too summarized, let's bust open those steps. Several of
these steps currently require you to write some glue code, which will
be indicated \[like this\]. 



## Step 1: Your Build (Server/Task/Script)

1. \[build glue\] build your application
2. run [dump_syms][] on your build dir to convert native symbols to the [breakpad .sym format][sym]
3. \[http glue\] upload the resulting .sym to your symbol server
4. \[http glue\] upload your binaries to be deployed to clients

> This stage of the pipeline is largely covered by the [symbolic][] family of crates,
> with [dump_syms][] wrapping all that functionality up into one CLI application.

All that really needs to happen in your build is to grab the "debuginfo" or "symbols"
for your application. (Everyone has different names for different subsets of this stuff,
but "symbols" is kind of the common terminology in the minidump world, so let's go with
that).

dump_syms does this by converting the native versions of that
info into a platform-agnostic format with all the details your crash-reporting
infrastructure doesn't need ripped out.

With that information isolated and packaged up, you are now free to ship fully "[stripped][strip]"
binaries, as your crash report processor will be able to retrieve that information
from your symbol servers (Step 2).

Technically speaking, dump_syms is optional, but it simplifies a lot of things
and amortizes a lot of expensive steps, so we'll be assuming you want to use it.
That said, it's still useful to understand the underlying infrastructure that
dump_syms simplifies away, as some details of that system still remains.



### What Are Symbols And How Are They Used?

Your symbols are enormous tables (like 100s of MB or even many GB)
that your compiler emits as part of the build (depending on various flags). 
These tables map every single address in your binary to information like:

* "what source file/function/line is this address"
* "how do you unwind the stack from here" ("CFI", "call frame information", "unwind tables")
* "what functions were inlined here"
* "how do you recover function arguments from here"

For crash reporting, the first two are really important, the third is nice to have,
and the last isn't very important. This information allows us to produce human-readable
backtraces for all your threads at the time of the crash.

These tables are generally represented in native platform-specific formats like DWARF or PE32+,
and can be stored in your executable, shared libraries, intermediate artifacts, 
or dedicated debug files like [pdbs][].

In the terminology of minidumps, your application contains several *modules*, and each
module can have a *code file* and *debug file*. Your executable is one module, and every
dynamic/shared library it loads is another module. Those native binaries (before stripping)
are their own *code files*. Things like [pdbs][] are *debug files*.

Compilers generally have some system for generating timestamps/hashes/guids/uuids that uniquely
identify the code/debug files for a particular build. These ids are your *code ids*, *debug ids*,
and *versions*, and should be available in your binaries/libraries at runtime.

When a crash happens, the minidump generator (Step 3) will gather up those various ids and
store them in your minidump as [Module Records][minidump-trait]. When processing a minidump
(Step 4), these records are used to query your symbol server (Step 2) for the symbols it needs.

Keen-eyed readers at this point may notice a problem: the specific shared libraries that your
application will link to on the client aren't available at build time! This is what we in the biz
call A Huge Fucking Pain In The Ass, and different platform vendors do better/worse jobs of helping
you solve it.

Some vendors make system symbols available locally, so moving processing (Step 4) onto the client
has some merits, but this isn't currently supported by our pipeline. It's also inherently sketchy
because we *are* talking about a system that just crashed our application. It's best to not
overstay our welcome and to just do the minimum amount of work to submit the report.

Some vendors host system symbols online. For instance, [Microsoft's symbol servers][microsoft-symbol-server]
host the code files and debug files for every system library they've ever shipped ever.
We'll discuss that in more detail in Step 2, as Microsoft's protocol is the entire basis for it.

Other vendors tell you to go fuck yourself and make it impossible or difficult to get system symbols.

Companies like Mozilla and Sentry have tons of random workflows for trying to scrape and process
the symbols for platforms we care about however we can. This includes things like "yeah this one
person just runs a bunch of scripts on various macos/xcode versions". This Sucks.




## Step 2: Your Symbol Server

1. \[http glue\] receive symbols from the build
2. \[storage glue\] store the symbols
3. \[http glue\] host a symbol server endpoint for Step 4 to query
    1. For native symbols, we support the [microsoft symbol server protocol][microsoft-symbol-server]
    2. For .syms, we support the [tecken symbol server protocol][tecken]

> TLDR: run a static file server that hosts a .sym for a module at `DEBUG_FILE/DEBUG_ID/DEBUG_FILE.sym` (DWrite.pdb/c10250ffba478e770798871932c7d8c51/DWrite.sym).

In the previous section we mentioned how [Microsoft's symbol servers][microsoft-symbol-server]
host symbols for basically every system library they've ever shipped, which fucking rules.
Here's another fun fact: the Minidump format itself was also created by Microsoft.

Given these two facts, it may not surprise you to learn that these two pieces of technology
were built to be slapped together. Whether you open an Official Windows Minidump in an
Official Microsoft Tool like [windbg][], or process an extended breakpad-style minidump
with something like [minidump-stackwalk][], the symbol server protocol is at the heart of it.

Thankfully this protocol is incredibly simple, and is simply a static file server with
files hosted at the appropriate path schema. Let's look at a particularly copy of the
Microsoft system library DWrite.dll:

```
code_file        = "C:\Windows\System32\DWrite.dll"
code_identifier  = "29a9e8ad27f000"
debug_file       = "DWrite.pdb"
debug_identifier = "c10250ff-ba47-8e77-0798-871932c7d8c5-1"
```

Microsoft's servers host the native code_file and debug_file at `/FILE_NAME/ID/FILE_NAME`:

* code_file: https://msdl.microsoft.com/download/symbols/DWrite.pdb/c10250ffba478e770798871932c7d8c51/DWrite.pdb
* debug_file: https://msdl.microsoft.com/download/symbols/DWrite.dll/29a9e8ad27f000/DWrite.dll

(Note how code_file has the directory removed, and debug_identifier has the `-`'s removed!)

[Mozilla's servers][tecken] host the .sym as if it was the debug_file, but with the second `.pdb` changed to `.sym`:

* https://symbols.mozilla.org/DWrite.pdb/c10250ffba478e770798871932c7d8c51/DWrite.sym

(Note that dump_syms merges the info from the code_file and debug_file into one sym!)

Our tooling for processing minidumps (Step 4) technically supports both of these protocols,
although the .sym format is preferred, and the native format is disabled by default
(it's hackily implemented by downloading the binaries and running dump_syms to get a .sym,
but in the future we'd like to cut out the middle-man and handle binary formats natively).

In either case you give it a URL prefix to append the query paths to 
(https://symbols.mozilla.org/, https://msdl.microsoft.com/download/symbols/).
Only the full query paths need to resolve to anything. We recommend making symbol servers
case-**in**sensitive, but some third-party servers aren't. Our tooling tries
to preserve casing at all points to interoperate with all systems.

If we *do* move towards handling more native debuginfo, then we may also want to support
things like the [elfutils debuginfod protocol][debuginfod], which various linux distros
are increasingly hosting their own system symbols on, but that's far-future work.





## Step 3: Your App (Running On The Client, Crashing, And Reporting)

1. spawn two processes: your app, and the crash-monitor (either ship two binaries, or spawn two instances of one)
2. in your app, create a [minidumper][]::Client, which will act as a signal handler
3. in your crash-monitor, create a [minidumper][]::Server, which will create a minidump for your app
4. \[http glue\] send the report+minidump to your servers

> This stage of the pipeline is handled by the [crash-handling][] family of crates,
> with [minidumper][] wrapping it all up into one convenient library.

This is the part I'm fuzziest on, so there will be less details for now, but I'll try my best.

It may be surprising/annoying to learn that this system requires you to have two
binaries running on the client. In the past we tried to do everything in one application,
and it kind of works ok, but it's an inherently messy and problematic thing to do.

Even though a minidump is *mini* it still has a fair amount of data-collection to do,
and then needs to open up an http connection and send the minidump to your servers.
This isn't that big of a deal for a normal application
to do, but it's a lot messier to do in an application that **literally just crashed,
possibly due to a memory corruption bug**.

The multi-process architecture is simply more reliable, and the only thing supported
by this pipeline. That said, *some* work does still need to be done in your app:

* detecting a crash (handling signals)
* gathering a [crash-context](crash_context) (some minimal core details)
* sending the [crash-context](crash_context) to the crash-monitor process

At this point, the crash-monitor process needs to:

* gather all the other details about the system and crashed process
* [write a minidump][minidump-writer]
* send that minidump (and potentially other details) to your crash reporting server

This is mostly just a bunch of platform-specific code for enumerating threads,
dumping registers, getting stack memory, getting system info, and so on.




## Step 4: Your Crash Report Processor Server

1. \[http glue\] receive a report+minidump
2. run [minidump-stackwalk][] `--json --symbols-url="https:/your.symbol.server.com/"` to produce [a json report][json-schema]
3. \[http glue\] send the json report to crash reporting application (Step 5)

> This stage of the pipeline is handled by the [rust-minidump][] family of crates,
> with [minidump-stackwalk][] wrapping it all up into one CLI application, which itself
> is just a thin client around the [minidump-processor][] library.

I'm emphasizing [minidump-stackwalk][] and the [json report][json-schema] here because
they're stable interfaces with proper schemas/docs, but if you don't like that stuff and
are fine with potential API breakage in new versions, then you can also totally use
[minidump-processor][] directly and convert the in-memory structures into whatever you want.

If you use minidump-stackwalk, fetching symbols from a symbol-server over http will be
enabled by default, while it will be disabled by default in minidump-processor. Either
way, this functionality is currently provided by the [breakpad-symbols][] library,
although we have a very Dread Pirate Roberts relationship with it, in that every night
we go to promise ourselves that we'll kill it Soon (and replace it with something
based on [symbolic][]).

Mozilla likes the minidump-stackwalk + http + json-report workflow, Sentry likes the 
minidump-processor + hackily-intercept-and-fulfill-symbol-queries-with-their-own-backend + produce-their-own-custom-reports workflow.
It takes all kinds. :)

minidump-stackwalk is primarily designed around parallelism by spawning multiple
instances of it that all share an on-disk cache, but we're starting to teach it to
be more async and concurrent within one process.



## Step 5: Your Processed Crash Report Display

1. digest the [json crash report][json-schema] into a database
2. build some kind of CRUD app on top of that database
3. build a web-based UI for viewing crash reports 

At this point you're kind of outside of this project's purview, although maybe it shouldn't be?

Some tooling from step 4 provides basic human-readable views:

* [minidump-stackwalk][] `--human` produces a simple printout of crash info and backtraces
* [minidump-debugger][] is a desktop GUI with much the same functionality but more... GUI

More complex stuff like search/aggregation/monitoring puts you more in the territory of
"just pay for [sentry.io]", although mozilla [has its own infra][crash-stats] so it's
not *impossible* to build your stuff. Just, a lot of work.


# A Rough Diagram Of The Pipeline

On the off-chance that this helps you visualize all the moving parts, here's a vague diagram of everything
involved. I've broken the architecture into 3 major sections:

* your build
* your client (user)
* your server (you)

The client and server are further broken up into separate processes.

Rough atlas:

* solid arrows: code invoking
* dashed arrows: data flow
* diamond boxes: data (files/structs)
* square boxes: specific rust-minidump/crash-handling/symbolic crates
* round boxes: "glue" (your problem for now)


```mermaid
graph TD;
subgraph build
  cargo
  dump_syms
  http-symbol-sender(http-symbol-sender)
  binary{.exe/.pdb}
  sym{.sym}
end

subgraph client
  subgraph app
    YOUR_ACTUAL_APP(YOUR ACTUAL APP)
    minidumper::Client
    crash-handler
  end

  subgraph crash-monitor
    minidumper::Service
    minidump-writer
    http-dump-sender(http-dump-sender)
    context{CrashContext}
    dump{.dmp}
  end
end

subgraph server
  subgraph processor-server
    http-dump-receiver(http-dump-receiver)
    minidump-processor
    minidump
    structMinidump{Minidump}
    report{report.json}
  end
  subgraph symbol-server
    tecken(static-file-server)
    http-symbol-receiver(http-symbol-receiver)
  end
  subgraph display
    socorro(database?)
    webapp(webapp?)
  end
end

cargo -.-> binary
binary -.-> dump_syms
binary -.-> deploy(deploy)
dump_syms -.-> sym
sym -.-> http-symbol-sender

crash-handler ---> minidumper::Client
minidumper::Client ---> minidumper::Service
minidumper::Service ---> minidump-writer
minidump-writer -.-> dump
dump -.-> http-dump-sender
minidumper::Service ---> http-dump-sender 
minidumper::Service -.-> context
context -.-> minidump-writer

http-dump-receiver ---> minidump-processor
http-dump-receiver ---> minidump
minidump -.-> structMinidump
structMinidump -.-> minidump-processor
tecken -. .sym .-> minidump-processor
minidump-processor -.-> report
report -.-> http-dump-receiver
http-dump-receiver -. report.json .-> socorro

http-symbol-sender -. .sym .-> http-symbol-receiver
http-dump-sender -. .dmp .-> http-dump-receiver
```

[pdb]: https://llvm.org/docs/PDB/index.html
[sym]: https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md
[sentry.io]: https://sentry.io/
[dump_syms]: https://github.com/mozilla/dump_syms
[crash-handling]: https://github.com/EmbarkStudios/crash-handling/
[crash-context]: https://github.com/EmbarkStudios/crash-handling/tree/main/crash-context
[rust-minidump]: https://github.com/rust-minidump/rust-minidump
[minidump-writer]: https://github.com/rust-minidump/minidump-writer
[minidumper]: https://github.com/EmbarkStudios/crash-handling/tree/main/minidumper
[minidump-processor]: https://github.com/rust-minidump/rust-minidump/tree/main/minidump-processor
[minidump-stackwalk]: https://github.com/rust-minidump/rust-minidump/tree/main/minidump-stackwalk
[minidump-debugger]: https://github.com/Gankra/minidump-debugger
[tecken]: https://tecken.readthedocs.io/en/latest/download.html#download
[microsoft-symbol-server]: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols
[minidump-trait]: https://docs.rs/minidump/latest/minidump/trait.Module.html
[strip]: https://en.wikipedia.org/wiki/Strip_(Unix)
[windbg]: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools
[minidump-ours]: https://docs.rs/minidump/latest/minidump/#what-is-a-minidump
[minidump-msft]: https://docs.microsoft.com/en-ca/windows/win32/debug/minidump-files?redirectedfrom=MSDN
[debuginfod]: https://sourceware.org/elfutils/Debuginfod.html
[symbolic]: https://github.com/getsentry/symbolic
[json-schema]: https://github.com/rust-minidump/rust-minidump/blob/main/minidump-processor/json-schema.md
[crash-stats]: https://crash-stats.mozilla.org/
[breakpad-symbols]: https://github.com/rust-minidump/rust-minidump/tree/main/breakpad-symbols
