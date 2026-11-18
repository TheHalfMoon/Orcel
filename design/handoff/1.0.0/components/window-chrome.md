# Window chrome

The Windows 11 frame drawn by the app: titlebar and caption buttons.

Surfaces: control-room|desktop

## Anatomy

- Titlebar 40, color.background, drag region.
- Mark 16 and window title.
- Optional Shadow Mode switch and background task indicator.
- Caption buttons 46 × 40 at the inline end.

## States

- **default**: Glyphs color.text.
- **hover**: Minimise and maximise color.hover; close uses the Windows system close colour with a white glyph (system, not a brand token).
- **focus**: Caption buttons show the color.focus ring when reached by keyboard.
- **active**: color.selected.
- **disabled**: Maximise disabled at fixed-size windows, color.text-subtle.
- **loading**: Does not apply
- **error**: Does not apply
- **selected**: Window inactive: title color.text-subtle.

## Keyboard

Alt+Space opens the system menu; Alt+F4 closes; Tab reaches in-titlebar controls after the skip link. Caption buttons follow Windows behaviour.

## Accessibility

- Role: toolbar for in-titlebar controls; caption buttons are buttons.
- Accessible name: "Minimize", "Maximize", "Close".
- Focus indicator: 2px outline in color.focus with a 2px offset on :focus-visible (offset -2px inside lists and scroll areas); on color.shadow-bg the ring uses color.shadow-accent.
- Hit area: At least 24×24 CSS px; 32 by default in the Control Room, 40 on the website.
- 200% zoom: Reflows; labels wrap rather than truncate; no horizontal scrolling.
- Forced colours: Keeps a visible border or outline in CanvasText/ButtonText; state is also carried by words or icons, never colour alone.
- Right-to-left: Content uses logical properties; caption buttons follow the Windows system layout for the locale.

## Motion

None. Under prefers-reduced-motion every transition and animation uses motion.duration.reduced (0 ms); no meaning depends on motion.

## Responsive

At 480×320 the title truncates and the Shadow Mode switch becomes icon-only. Right-to-left keeps caption buttons where Windows puts them for the system locale.

## Implementation

Tauri decorations off with data-tauri-drag-region; Snap Layouts hit-testing is an engineering item outside design integration.
