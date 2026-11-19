# NAME

Path::Secure - Say whether an account other than you could change a path, or make sure it cannot

# VERSION

version 0.001

# SYNOPSIS

```perl
use Path::Secure qw{exposed secure};

my $why = exposed( '/srv/app/config', trust_group => $) + 0 );
die "refused: $why\n" if defined $why;

my @changed = secure( '/srv/app/config', upto => '/srv/app' );
print "made $_ safe\n" for @changed;
```

# DESCRIPTION

Before a program reads a file that tells it what to do, or runs one, it has to
know that nobody else wrote it.  Checking the file is not enough.  An account
that can write a directory above the file can rename the file away and put its
own in its place, and an account that can write the directory holding a
symbolic link can point the link somewhere else.  ["exposed"](#exposed) answers the
whole question: could an account other than you change this path, or a
directory above it, or a link on the way to it?  ["secure"](#secure) changes the modes
that it can, so that the answer is no.

The same check exists in [File::Temp](https://metacpan.org/pod/File%3A%3ATemp), as the private `_is_safe` and
`_is_verysafe`, and in [Net::OpenSSH](https://metacpan.org/pod/Net%3A%3AOpenSSH), for its control directory.  This
distribution makes it public, with an option to trust a group, and returns the
reason rather than a bare false.

## The policy

These are the rules that both functions apply.  A _path_ here is the path
that the caller passes.  Its _entries_ are every directory that resolving the
path looks in, from `/` down, every symbolic link that it follows, and the
entry that it finally names, which is the _target_.

- An entry is safe from an account when that account cannot write it, and
cannot replace it.  Root can do anything, so an entry that root owns or can
write is not a risk that a check can remove.  So root is trusted, as is the
effective uid of the process, `$>`.  Nobody else is.
- An entry is exposed when another account owns it, other than root.  The owner
of a file can change its mode at any time, so no mode makes it safe.
- An entry is exposed when every account can write it (`S_IWOTH`), or when its
group can write it (`S_IWGRP`) and that group is not one that the caller
trusts with `trust_group`.  No group is trusted by default, not even the
primary group of the process: a group usually has members that the process
does not know about.
- A directory above the target that has the sticky bit (`S_ISVTX`) is safe even
when other accounts can write it, because then they can rename or remove only
the entries that they own, and the next entry down has to pass the owner rule.
That is how `/tmp` works.  It still has to pass the owner rule itself.
- The target gets no pass for the sticky bit.  An account that can make a new
entry in a directory can make one whose name the program will read, even if it
cannot replace the entries that are there.  `sticky_target => 1` gives the
pass to a target that is a directory, for a caller that only makes new entries
in it with `O_EXCL` and reads nothing that it did not make.
- A symbolic link is followed one step at a time, as the kernel does.  The link
itself has to pass the owner rule: in a sticky directory, the owner of a link
can replace it.  Its own mode means nothing.  The directory that holds it is
an entry above the target, so whoever can write that directory could point
the link somewhere else.  What the link names is resolved in turn, and so is each link after
it.  A chain of more than 40 links, which is the limit of Linux, is a reason.
- A `..` leaves a directory without making it an entry above the target,
because the kernel resolves `..` from the directory's own parent, which a
write to the directory cannot change.
- A relative path is taken from the current directory, as the kernel would take
it.  Its real path, from [Cwd](https://metacpan.org/pod/Cwd), is where the walk starts, so every directory
above the current one is checked too.

## What it does not cover

The check reads owners and mode bits, and nothing else that can grant a
write.  It does not read access control lists (POSIX ACLs, NFSv4 ACLs), Linux
capabilities such as `CAP_DAC_OVERRIDE` or `CAP_FOWNER` held by another
process, file attributes such as `chattr +i`, the options that a filesystem
is mounted with, or the policies of SELinux or AppArmor.  A filesystem that
does not keep POSIX owners, such as FAT or many network mounts, reports what
its driver makes up.  A file system mounted by another account, such as a
FUSE mount, is safe only as far as its driver tells the truth.

It does not look for another name of the same file: a hard link in a directory
that other accounts can write lets them unlink that name, not change the file,
so it does not matter here.

## Chown giveaway

On some systems an account can give a file that it owns to another account
with `chown`.  POSIX calls the opposite `_POSIX_CHOWN_RESTRICTED`, and asks
for it with `pathconf(_PC_CHOWN_RESTRICTED)`.  Linux and the BSDs restrict
`chown` to root.  Where it is not restricted, an entry that the process owns
may have been made by another account, which can still hold a descriptor that
it opened for writing before it gave the file away.  No mode or owner shows
that, so this module cannot see it, on any system.  It does not change the
result.  [File::Temp](https://metacpan.org/pod/File%3A%3ATemp) asks `_PC_CHOWN_RESTRICTED` only to decide whether to
check the directories above a path.  This module always checks them.

## The race that it cannot close

Each answer is true when it is made.  Between the check and the moment the
program opens the path, the modes and the entries can change.  The check is
worth making because of what it rules out: when every entry passes, no account
other than root and the caller can make such a change, so the answer stays
true until one of them changes it.  Open the path after the check, and if the
check matters, compare `dev` and `ino` of what you opened with `stat` of
the path.

# FUNCTIONS

## exposed

`($path, %option)`.  Why an account other than the effective uid or root
could change `$path` or an entry on the way to it, as ["The policy"](#the-policy) says, or
undef when no such account can, in list context as well.  The reason is one
clause in English that names the entry at fault, such as `every account can
write /srv/shared`, so a caller can put it after `refused:` in a message.  It checks the entries from
`/` down and gives the first reason that it finds.

A path that is not there is not safe: the reason is that the first missing
entry `is not there`.  An entry that it cannot look at, for example in a
directory that it cannot search, gives the error of `lstat`.

The options:

- trust\_group

    A gid, or a reference to an array of gids.  An entry that one of these groups
    can write is not exposed for that.  The default trusts no group.

- sticky\_target

    True to give the target the pass for the sticky bit that the directories above
    it get, when the target is a directory.  The default is false.

Dies when `$path` is undefined or empty, when an option is not one of these,
when `trust_group` is not a whole number or an array of them, and on a system
whose files do not have POSIX owners and modes, such as Windows or VMS, rather
than call a path safe there.

## secure

`($path, upto => $top, %option)`.  Changes the modes of `$path` and of
the directories above it, up to and including `$top`, so that ["exposed"](#exposed)
finds nothing with the same `trust_group`.  Returns the paths that it
changed, from the top down, and an empty list when it changed nothing.

It works on the real path of `$path`, from [Cwd](https://metacpan.org/pod/Cwd), because `chmod` follows
symbolic links.  For the target, it takes away the write bit of every account,
and the write bit of the group unless `trust_group` trusts the group.  For
each directory above the target, up to and including `$top`, that another
account or a group that it does not trust can write, it adds the sticky bit.
That keeps the directory writable for whoever shares it, and stops them
replacing what the caller owns there.  The option `private => 1` takes
those write bits away from the directories instead.

It changes nothing above `$top`, and nothing that the effective uid does not
own unless that is root.  So it can fail, and it does all of its checks before
its first change.  It plans every mode first.  Then it runs the check of
["exposed"](#exposed) on `$path` as given, with the planned modes in place of the real
ones, so that a directory above `$top`, a link on the way to the real path,
or an entry that another account owns stops it before anything changes.  Then
it dies if a planned change is to an entry that the effective uid cannot
change.  Only then does it change the modes, from `$top` down, so that each
parent is safe before its child changes.  Before each change it looks at the
entry again, and dies if it is not the entry that it planned for.  At the end
it runs ["exposed"](#exposed) again, and dies with its reason if the path is still
exposed, so a caller never gets a partial success that looks like a full one.

The options:

- upto

    Required.  A directory that `$path` is in, or `$path` itself.  It is the
    highest directory that `secure` may change.

- trust\_group

    As for ["exposed"](#exposed).

- private

    True to take away the write bits of other accounts and of groups that it does
    not trust from the directories above the target, rather than to add the sticky
    bit.  The default is false.

Dies, having changed nothing, for what ["exposed"](#exposed) dies for, when `upto` is
missing or is not a directory, when `$path` is not there or is not in
`$top`, when the planned modes still leave the path exposed, and when a
planned change is to an entry that the effective uid does not own, unless that
is root.  Dies, after the
changes that it lists, when a `chmod` fails or an entry changed under it.

The race: between the second look at an entry and the `chmod`, an account
that can write the parent of that entry could put another entry in its place,
and the `chmod` would follow it if it is a link.  Going from the top down
closes that for every entry that the caller owns, because its parent is sticky
or closed by then.  It remains for the entries that root owns, and for `$top`
itself, whose parent `secure` may not change.

## stat\_entry

`($path)`.  What `lstat` says about `$path`.  It is not exported.  The two
functions call it for every entry, so that a test can replace it to give an
entry another owner, which an account that is not root cannot make.

## change\_mode

`($mode, $path)`.  `chmod` of `$path` to `$mode`, and what `chmod`
returns.  It is not exported.  ["secure"](#secure) calls it for each change, so that a
test can replace it.

# AUTHORS

Current Maintainers:

- George S. Baugh <george@troglodyne.net>

# COPYRIGHT AND LICENSE

Copyright (c) 2026 Troglodyne LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
