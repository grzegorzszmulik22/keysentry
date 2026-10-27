# Dashboard design direction

For the agents building `src/dashboard/client`. The dashboard is a local page that answers three questions for a
developer who just heard about a breach: where do my keys live, what is at risk, and what exactly will keysentry do
if I press this button. It must feel calm and exact, like a well-kept key cabinet, never like an alarm panel.

## The one memorable thing: the key cabinet

Keys are shown as **key tags** hanging in a cabinet, not as table rows or generic cards. A tag is a small rounded
rectangle with a punched hole on its left edge (a circle cut out with a CSS `mask` radial gradient), the provider
name, the key hint in monospace, and one line of state. The key map screen is a wrap grid of tags; selecting a tag
opens a side panel listing its hooks (every place the key lives). All the boldness of the design goes here. Every
other screen is quiet: text, plain tables, generous space.

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │ keysentry          project-name                What keysentry can access │
 ├────────────┬──────────────────────────────────────────────────────────┤
 │ Overview   │  Your keys                                               │
 │ Keys       │                                                          │
 │ Connect    │  (o) OpenAI        (o) OpenRouter     (o) Stripe          │
 │ Rotate     │      sk-proj…ABCD      sk-or-v1…f00       sk_live…9xQ      │
 │ Autopilot  │      3 places · 41 days  1 place · 3 days  2 places        │
 │ Activity   │      In git history    Armed             Rotate by hand    │
 │ Notify     │                                                          │
 │ Approvals  │  (o) Session secret  ...                                 │
 │ Settings   │                                                          │
 └────────────┴──────────────────────────────────────────────────────────┘
```

## Colour tokens

Defined as CSS custom properties on `:root`, redefined under `@media (prefers-color-scheme: dark)`. Every text
pair below meets WCAG AA (4.5:1 for body text, 3:1 for large text and UI outlines); check new pairs before use.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#F3F6F8` porcelain | `#152030` cabinet slate | page background |
| `--surface` | `#FFFFFF` | `#1C2A3D` | panels, tags, dialogs |
| `--ink` | `#1B2533` graphite | `#E6ECF2` | text, primary buttons |
| `--muted` | `#566170` | `#A5B1BF` | secondary text |
| `--line` | `#D3DAE1` | `#30405A` | decorative borders and dividers only |
| `--control-line` | `#7B8594` | `#71839C` | input, checkbox and button outlines (≥ 3:1 against `--bg` and `--surface`) |
| `--brass` | `#8A5E0C` | `#D8A64A` | key tags' hole ring and provider line, the focus ring |
| `--ok` | `#1D7349` | `#5CC48F` | verified, safe |
| `--attention` | `#9A4A00` | `#F0A35E` | needs rotation, unconfirmed |
| `--stop` | `#B42318` | `#F28B82` | failed, exposed in git history |
| `--info` | `#24569E` | `#8DB4F0` | links, neutral notices |

Status colours never carry meaning alone: every state has a word ("Verified", "Needs rotation", "In git history",
"Armed", "Rotate by hand").

## Type

- UI and body: `system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif` at 16px, line-height 1.5.
- Key hints, fingerprints and commands only (content, never labels): `ui-monospace, "Cascadia Mono", "SF Mono",
  Menlo, Consolas, monospace` at 0.9375em.
- Scale (1.25 ratio): 13, 16, 20, 25, 31px. Page title 25px weight 650; section titles 20px weight 600; body 16px
  400; small 13px only for tag metadata. Sentence case everywhere; no all-caps labels; no eyebrow labels above
  headings.
- Numbers use `font-variant-numeric: tabular-nums`.
- Text columns max 72 characters wide; left aligned; never justified.

## Space, shape, motion

- Spacing scale: 4, 8, 12, 16, 24, 32, 48px. Panels use 24px padding; the key grid gap is 16px.
- Radii by role, not one radius for everything: tags 10px, buttons 6px, dialogs 12px, tables and inputs 4px.
- Elevation: none on the page; tags and dialogs use a 1px `--line` border; only open dialogs get a shadow
  (`0 12px 32px rgb(0 0 0 / 0.18)`).
- Focus: 3px `--brass` outline with 2px offset on every interactive element; never removed.
- Motion: only in answer to an action (panel opening 160ms ease-out, grace countdown ring). Nothing animates on
  page load. Under `prefers-reduced-motion: reduce`, transitions are 0ms.

## Components (in `components.ts`)

- `keyTag(cluster)`: the tag described above; keyboard focusable, Enter opens the hooks panel.
- `notice(kind, title, text)`: a bordered block with a status word; kinds ok, attention, stop, info.
- `confirmAction({ title, changes: string[], button })`: modal dialog repeating exactly what will change (each change
  a plain sentence from the server), the button named for the action ("Rotate 3 keys"), then the passkey step.
- `maskedValue()`: shows "Hidden" with a "Reveal" button (passkey), then the value, a "Copy" button that clears the
  clipboard after 30 seconds, and "Hide".
- `table(columns, rows)`: plain table with a caption, sticky header, no zebra striping.
- `emptyState(text, action)`: one sentence saying what to do next and one button.

## Copy

- Name things by what the user manages: "keys", "places", "platforms", "notifications", never "clusters",
  "consumers", "webhooks config".
- Buttons say what happens: "Rotate 3 keys", "Store token", "Arm autopilot", "Turn off autopilot". The result
  message reuses the verb: "Rotated 3 keys."
- Before every change, one sentence says what will happen and what will not ("keysentry will write the new key to
  2 Railway services and redeploy them. The old key stays valid for 15 minutes so you can undo.").
- Errors say what happened and what to do, without apology or alarm. No fear words ("hackers", "attack",
  "compromised" only when quoting a platform's own advisory).
- Empty screens are invitations: "No platforms connected yet. Connect Railway, Vercel, Render or Fly to see where
  your keys are deployed."
