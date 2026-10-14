# Components from Magic UI

These are from [Magic UI](https://magicui.design) (MIT, © Magic UI), copied
through its shadcn registry. They are changed only in these ways:

- the `cn` import is relative (`../../lib/utils`);
- the `"use client"` line is gone: Astro decides what runs in the browser;
- `terminal.tsx` takes a `title` for its window bar.

They are styled by the site's tokens in `src/styles/landing.css`, which use
shadcn's names (`background`, `border`, `muted-foreground`…), so the components
read them as they are. The home page's own sections are in `../landing`.
