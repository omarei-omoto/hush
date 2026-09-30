# Adding a key without pasting it into the chat

This is the flow that matters. You tell your agent *"set up the deploy script
with my personal fal key"*. It calls `hush_provision`, finds no set that holds
one yet, and calls `hush_add_secret`. A **secure input box opens on your
screen**:

```
┌─ hush — add a secret ──────────────────────────┐
│  needed to authenticate the deploy script      │
│                                                │
│  Service:  fal.ai                              │
│  Set:  personal-fal                            │
│                                                │
│  Paste the value for FAL_KEY:                  │
│  [••••••••••••••••••••••••]                    │
│                        [Cancel]  [Save]        │
└────────────────────────────────────────────────┘
```

You paste it there. It is encrypted straight into the vault. The agent gets back
`Stored FAL_KEY in "personal-fal" (this project). The value never entered this conversation.`

The key went from your keyboard to the vault. It was never in a prompt, never in
a transcript, never in a provider log.
