# DIP UI and branding foundation

This foundation standardizes the existing Phase 0–7 interface without changing product, workflow, storage, billing, or execution behavior. Phase 8 and the Document Agent are explicitly outside its scope.

## Brand system

DIP uses the official supplied logo and its cyan, blue, indigo, violet, and deep-navy family. Light-mode actions use blue (`#2563eb`); dark-mode actions use precision indigo (`#6366f1`) with restrained cyan live/AI accents. The palette is expressed through primitive brand tokens and semantic CSS roles in `src/app/globals.css`, not page-specific literals. Red is reserved for destructive and error states.

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

Light, dark, and system modes are supported. Preference is stored under `dip-theme`; a small pre-hydration script applies the resolved theme before React mounts, and system changes are observed while system mode is active.
