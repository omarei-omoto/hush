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
  **Choose a folder…** opens your system's folder picker (Finder's on a Mac)
  to add one to the folders hush looks in, and **Add a folder** takes a single
  codebase the same way; either also takes a pasted path. **Look again**
  re-crawls in the background. Dropping a global key on a codebase that is not
  set up sets it up with that key.
- **Global keys** are yours, kept once, never in a repository. **Drag a key onto
  a project** — in the sidebar or on Home — and it is part of that project: it
  gets the key whenever it runs. Nothing goes into the project's repository, and
  rotating the key is one edit that every project picks up. Without a mouse, a
  key's menu has **Use in a project…**. A project can take just that one key
  from a set, or the whole set.
- **Keys here**, for the project you are looking at: what a run gets, in the
  order the sets apply; the global keys it uses, each with **Remove**; and what
  its code reads. Only variables that look like credentials (`…_KEY`,
  `…_TOKEN`, `DATABASE_URL`, …) or that you already keep are listed, so
  `NODE_ENV` and `PORT` are never "missing". Your global sets are offered only
  when they hold something the code is missing.
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
name it, and it becomes a set, in your library if you have one, and used by
this project straight away. For a file that mixes things, tick **File them into
existing sets instead** to choose a set and a tag per key. Multi-line values
(PEM keys) survive intact. **Values never come back to the browser**: the review
gets names and masked previews only, and the plaintext stays server-side until
you import or discard it.
