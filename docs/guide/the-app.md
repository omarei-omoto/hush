# The app

Don't want to type commands? Don't.

```bash
hush ui
```

A local app in your browser that covers every project hush knows on this
machine, not just the folder you started it in.

- **Home** lists your projects with how many keys each gets. hush remembers a
  project whenever it runs in one, and **looks through the folders you choose**
  (your usual code folders until you do) for every codebase, set up for hush or
  not. Each one shows its stack (Next.js, Python, Go, …), its branch and when it
  was last worked on, which credentials its code reads and how many of those
  your global keys already have, and a warning when a plaintext `.env` sits in
  it. That is a names-only scan: no value, and nothing from a `.env`, is read.
  **Choose a folder…** opens your system's folder picker (Finder's on a Mac,
  Explorer's on Windows, zenity's or kdialog's on Linux) to add one to the
  folders hush looks in, and **Add a folder** takes a single
  codebase the same way; either also takes a pasted path. **Look again**
  re-crawls in the background. Dropping a global key on a codebase that is not
  set up sets it up with that key. A long list has a filter (name, folder or
  stack).
- **Every project has a ⋯ menu**, on Home and in the sidebar: **Open**, **Show
  in Finder** (Explorer on Windows, the file manager on Linux), **Copy path**,
  **Rescan**, **Hide** and **Remove from list…**. Hidden projects wait under
  **Hidden** on Home, where **Show** brings one back; a removed one is forgotten,
  and looking through your folders won't add it back — adding the folder again
  does. Neither touches the project's files, and using hush in a project never
  undoes either.
- **Global keys** are yours, kept once, never in a repository, and part of
  any project you give them to. They sit in the **right sidebar** by group,
  then set, then key, with a search when there are more than a few. **Drag a
  key, a set or a whole group onto a project** (in the left sidebar, on Home,
  or anywhere on an open project's page) and the project gets it whenever it
  runs. Nothing goes into the project's repository, and rotating a key is one
  edit that every project picks up. A group gives a project every set in it,
  including sets you add to it later. Without a mouse, each ⋯ menu has **Use
  in a project…**. Close the sidebar with its ×; the **Keys** tab on the right
  edge opens it again (on a narrow window it opens over the page).
- **Groups** are folders for your global sets, such as "AI stack": **New
  group** in the sidebar or on Global keys, or **Put in a group…** on a set.
  A group can be renamed or ungrouped from its ⋯ menu, and a project that used
  it keeps each set either way.
- **A project's page** shows what a run gets, in two parts. **Only
  <project>** is its own keys: kept for it alone, refused anywhere else, never
  in its repository, plus any sets in its repository's vault. **From your
  global keys** lists the groups, sets and single keys it uses, each with
  **Stop using here** or **Remove**. When two of them give the same key, a note
  says which one wins and lets the other win instead. Below that is what its
  code reads. Only variables that look like credentials (`…_KEY`, `…_TOKEN`,
  `DATABASE_URL`, …) or that you already keep are listed, so `NODE_ENV` and
  `PORT` are never "missing". Your global sets are offered only when they hold
  something the code is missing.
- **Moving between the two:** a project's own set or key has **Make global**.
  It joins your global keys (a single key goes into a global set you pick) and
  the project keeps getting it. A global set or key has **Keep for <project>
  only**. If other projects use it, the app names them and asks before taking
  it from them. A set in the repository's vault can be made global too; if
  teammates read that vault, the app asks first, since they stop getting the
  key from the repository.
- **Tidy up:** Global keys points out global sets that only one project uses
  as a whole, which is most likely that project's `.env` imported before keys
  could belong to one project. **Review** lets you make them that project's
  own.
- **Team** is who can decrypt. **Agent** shows what your coding agent is
  connected to and what it must ask you first. **Activity** is the audit log in
  plain sentences.

It binds to `127.0.0.1` only, needs a one-time token that travels in the link's
`#fragment` (so it never reaches a server log, and the page wipes it from the
address bar and history), refuses non-loopback `Host` headers, cannot be framed
by another page, and sends the browser **masked previews**, never the real
values. The exception is when you click **Reveal**, which asks for the
same approval as `hush get`, shows the value for fifteen seconds and writes the
reveal to the audit log.

**Dropping in a `.env`.** Drag files anywhere onto the page, or use **Import
.env**. Nothing is saved until you review it. The common case is one click:
name it (a project's own `.env` is named after the project), and it becomes a
set that this project uses straight away. On a project it is **Only
<project>** by default; choose **Global** to make it one of your global keys,
or, where the project already has a vault, **The repo, for the team**.
Importing on Global keys makes a global set. For a file that mixes things, tick **File them into
existing sets instead** to choose a set and a tag per key. Multi-line values
(PEM keys) survive intact. **Values never come back to the browser**: the review
gets names and masked previews only, and the plaintext stays server-side until
you import or discard it.
