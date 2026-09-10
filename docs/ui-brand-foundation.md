# DIP UI and branding foundation

This foundation standardizes the existing Phase 0–7 interface without changing product, workflow, storage, billing, or execution behavior. Phase 8 and the Document Agent are explicitly outside its scope.

## Brand system

DIP uses a warm, dark burgundy (`#6f1938`) as its primary brand color. The palette is expressed through semantic CSS roles in `src/app/globals.css`, not page-specific color utilities. Destructive actions remain a distinct red (`#b42318`), while success, warning, and information states have separate semantic roles.

The primary text/background pair and interactive colors meet WCAG AA contrast. The default typography remains Inter for English and uses the already-installed Noto Sans Arabic for Arabic. Arabic receives its own line-height and is activated through document direction/language selectors.

## Component conventions

- Use semantic tokens such as `bg-card`, `text-muted-foreground`, `border-input`, and `ring-ring`.
- Use shared primitives from `src/components/ui` for buttons, fields, cards, feedback, progress, dialogs, menus, and sheets.
- Prefer logical properties (`ps`, `pe`, `start`, `end`) for bidirectional layout. Directional icons must be explicitly rotated when meaning changes in RTL.
- Interactive controls have visible focus, disabled, invalid, and loading states. Touch targets are at least 40–44px where practical.
- Motion is limited to short state and workflow transitions and is disabled when `prefers-reduced-motion` is active.
- Keep shadows subtle and reserve elevation for interactive or overlay surfaces.

## Responsive and accessibility baseline

The shared container is capped at 80rem with responsive inline padding. Navigation collapses into an accessible Radix sheet on small screens. Forms retain visible labels and error associations, feedback uses live regions where appropriate, progress exposes native accessibility semantics, and Radix primitives provide keyboard handling and focus management for dialogs and menus.

No dark-mode switch is introduced in this pass. Semantic tokens are structured so a future reviewed theme can be added without rewriting components.
