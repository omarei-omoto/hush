# The app

Don't want to type commands? Don't.

```bash
hush ui
```

A local app in your browser, built around what you came to do:

- **Project** answers "does my app have what it needs?" hush scans the code for
  the variables it reads and marks each one provided (and by which set) or
  missing. A missing key that one of your other sets already has comes with a
  **Use that set** button, so you don't type it twice. Below that are the sets
  a run gets, in the order they apply, with every key visible and any key that
  a later set overrides struck through.
- **Library** is your own catalog. **Team** is who can decrypt. **Agent** shows
  what your coding agent is connected to and what it must ask you first.
  **Activity** is the audit log in plain sentences.

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
