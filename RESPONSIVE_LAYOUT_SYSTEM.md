# JRTS Responsive Layout System Specification
**Document Type**: Technical Reference  
**Version**: 1.0  
**Audience**: Developers & Designers

---

## 1. RESPONSIVE BREAKPOINT SYSTEM

### 1.1 Breakpoint Definitions & Device Mapping

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RESPONSIVE BREAKPOINT HIERARCHY                  │
├──────────┬──────────┬─────────┬──────────┬─────────────────────────┤
│ Label    │ Range    │ Device  │ Use Case │ Primary Components      │
├──────────┼──────────┼─────────┼──────────┼─────────────────────────┤
│ xs       │ 320-479  │ Phone   │ Portrait │ Tab bar nav, full-width │
│          │ pixels   │ (small) │ mode     │ content, stacked forms  │
├──────────┼──────────┼─────────┼──────────┼─────────────────────────┤
│ sm       │ 480-767  │ Phone   │ Landscape│ Tab bar nav, wider      │
│          │ pixels   │ (large) │ & tablet │ cards, 2-col grids      │
├──────────┼──────────┼─────────┼──────────┼─────────────────────────┤
│ md       │ 768-1023 │ Tablet  │ Portrait │ Sidebar toggle, 3-col   │
│          │ pixels   │         │ mode     │ grids, form w/ output   │
├──────────┼──────────┼─────────┼──────────┼─────────────────────────┤
│ lg       │1024-1439 │ Desktop │ Primary  │ Sidebar visible, 4-col  │
│          │ pixels   │         │ & tablet │ grids, side-by-side     │
│          │          │         │ landscape│ layout                  │
├──────────┼──────────┼─────────┼──────────┼─────────────────────────┤
│ xl       │ 1440+    │ Large   │ Premium  │ Full layout, max-width  │
│          │ pixels   │ desktop │ desktop  │ container, enhanced     │
│          │          │         │          │ spacing                 │
└──────────┴──────────┴─────────┴──────────┴─────────────────────────┘
```

### 1.2 CSS Media Query Syntax

**Mobile-First Approach** (Progressive Enhancement):

```css
/* Base styles apply to all viewports (mobile first) */
.component {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

/* Tablet and larger */
@media (min-width: 768px) {
  .component {
    flex-direction: row;
    gap: 1rem;
  }
}

/* Desktop and larger */
@media (min-width: 1024px) {
  .component {
    gap: 1.5rem;
  }
}
```

**NOT Recommended** (Desktop-first, harder to maintain):
```css
/* Avoid this approach */
@media (max-width: 1024px) { /* Rules */ }
@media (max-width: 768px) { /* Rules */ }
```

### 1.3 Breakpoint Constants (CSS Variables)

```css
/* In styles/tokens.css */
:root {
  /* Breakpoints as variables */
  --breakpoint-xs: 320px;
  --breakpoint-sm: 480px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 1024px;
  --breakpoint-xl: 1440px;
  
  /* Derived values for convenience */
  --breakpoint-md-up: 768px;      /* >= tablet */
  --breakpoint-lg-up: 1024px;     /* >= desktop */
  --breakpoint-below-md: 767px;   /* < tablet */
}

/* Mixin approach (if using SCSS) */
@mixin respond-to($breakpoint) {
  @if $breakpoint == 'sm' {
    @media (min-width: 480px) { @content; }
  }
  @else if $breakpoint == 'md' {
    @media (min-width: 768px) { @content; }
  }
  @else if $breakpoint == 'lg' {
    @media (min-width: 1024px) { @content; }
  }
  @else if $breakpoint == 'xl' {
    @media (min-width: 1440px) { @content; }
  }
}
```

---

## 2. RESPONSIVE LAYOUT GRID SYSTEM

### 2.1 Container Query System

**Main Content Container Widths**:

```
Device Type          Viewport Width    Container Width   Padding
────────────────────────────────────────────────────────────────
Mobile (xs)          320-479px         100%              8px
Mobile (sm)          480-767px         100%              12px
Tablet (md)          768-1023px        728px             20px
Desktop (lg)         1024-1439px       984px             20px
Large Desktop (xl)   1440px+           1320px            60px
```

**CSS Implementation**:
```css
/* Base: Mobile responsive padding */
.app-container {
  padding: 0 0.75rem;  /* 12px */
  max-width: 100%;
}

/* Tablet: Centered container */
@media (min-width: 768px) {
  .app-container {
    padding: 0 1.25rem;  /* 20px */
    margin: 0 auto;
  }
}

/* Desktop: Max-width constraint */
@media (min-width: 1024px) {
  .app-container {
    padding: 0 1.25rem;
    max-width: 1024px;
  }
}

/* Large Desktop: Wider container */
@media (min-width: 1440px) {
  .app-container {
    padding: 0 3.75rem;  /* 60px */
    max-width: 1400px;
  }
}
```

### 2.2 Column Grid Systems

**Dashboard Stats Grid**:
```
┌────────────────────────────────────────────────────────────┐
│ MOBILE (xs-sm)              TABLET (md)         DESKTOP (lg)│
├────────────────────────────────────────────────────────────┤
│ ┌──────────┬──────────┐     ┌──────┬──────┬──────┐         │
│ │ Stat 1   │ Stat 2   │     │ S1   │ S2   │ S3   │         │
│ ├──────────┼──────────┤     ├──────┼──────┼──────┤         │
│ │ Stat 3   │ Stat 4   │     │ S4   │ S5   │ S6   │         │
│ ├──────────┼──────────┤     │      │      │      │         │
│ │ Stat 5   │ Stat 6   │     │      │      │      │         │
│ └──────────┴──────────┘     └──────┴──────┴──────┘         │
│ 2 columns                  3 columns      6 columns        │
│ gap: 0.75rem              gap: 1rem       gap: 1rem        │
└────────────────────────────────────────────────────────────┘
```

**CSS**:
```css
.dashboard-home__stats {
  display: grid;
  grid-template-columns: repeat(2, 1fr);       /* Mobile: 2 cols */
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}

@media (min-width: 768px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(3, 1fr);     /* Tablet: 3 cols */
    gap: 1rem;
  }
}

@media (min-width: 1024px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(6, 1fr);     /* Desktop: 6 cols */
  }
}
```

**Module Card Grid**:
```
┌────────────────────────────────────────────────────────────┐
│ MOBILE (xs-sm)              TABLET (md)      DESKTOP (lg)   │
├────────────────────────────────────────────────────────────┤
│ ┌──────────────────────┐    ┌────────┬────────┐            │
│ │                      │    │        │        │            │
│ │   Card 1             │    │ Card 1 │ Card 2 │            │
│ ├──────────────────────┤    ├────────┼────────┤            │
│ │                      │    │        │        │            │
│ │   Card 2             │    │ Card 3 │ Card 4 │            │
│ └──────────────────────┘    └────────┴────────┘            │
│                                                             │
│ 1 column (100%)            2 columns      3-4 columns      │
│ minmax(100%, 100%)         (320px ea.)    (320px ea.)      │
└────────────────────────────────────────────────────────────┘
```

**CSS**:
```css
.module-grid {
  display: grid;
  grid-template-columns: 1fr;                  /* Mobile: 1 col */
  gap: 0.75rem;
  width: 100%;
}

@media (min-width: 768px) {
  .module-grid {
    grid-template-columns: repeat(2, 1fr);     /* Tablet: 2 cols */
    gap: 1rem;
  }
}

@media (min-width: 1024px) {
  .module-grid {
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 1rem;                                 /* Desktop: auto-fill */
  }
}
```

### 2.3 Flexible vs Fixed-Width Layouts

**When to Use Flexible (Recommended)**:
- Main content areas
- Cards in grids
- Form fields
- Lists and navigation

```css
.card {
  width: 100%;          /* Flexible, fills container */
  max-width: 1200px;    /* Optional cap */
}
```

**When to Fixed-Width (Rare)**:
- Sidebar (280px desktop)
- Tab bar (60px height)
- Header (56px height)

```css
.sidebar {
  width: 280px;         /* Fixed, doesn't collapse */
  flex-shrink: 0;       /* Prevent flex from shrinking */
}
```

---

## 3. RESPONSIVE SPACING SYSTEM

### 3.1 Margin & Padding Scale

**Variable Base Unit**: 0.5rem = 8px (1rem = 14px for typography)

```
Scale Unit  | px   | CSS Value | Common Use
────────────┼──────┼──────────┼──────────────────────────
Hairline    | 2px  | 0.125rem | Borders, separators
Tight       | 4px  | 0.25rem  | Small gaps, tight nesting
XSmall      | 8px  | 0.5rem   | Small padding, gaps
Small       | 12px | 0.75rem  | Medium padding
Base        | 16px | 1rem     | Standard padding/margin
Medium      | 20px | 1.25rem  | Larger padding
Large       | 24px | 1.5rem   | Large spacing
XLarge      | 32px | 2rem     | Section gaps
Huge        | 48px | 3rem     | Major separations
```

### 3.2 Responsive Spacing Adjustments

**Strategy**: Reduce spacing proportionally on smaller devices

```css
/* Mobile: Tight spacing */
:root {
  --spacing-xs: 0.5rem;     /* 8px */
  --spacing-sm: 0.75rem;    /* 12px */
  --spacing-md: 1rem;       /* 16px */
  --spacing-lg: 1.5rem;     /* 24px */
  --spacing-xl: 2rem;       /* 32px */
}

/* Tablet: Standard */
@media (min-width: 768px) {
  :root {
    --spacing-xs: 0.75rem;  /* 12px */
    --spacing-sm: 1rem;     /* 16px */
    --spacing-md: 1.25rem;  /* 20px */
    --spacing-lg: 1.75rem;  /* 28px */
    --spacing-xl: 2.5rem;   /* 40px */
  }
}

/* Desktop: Generous spacing */
@media (min-width: 1024px) {
  :root {
    --spacing-xs: 1rem;     /* 16px */
    --spacing-sm: 1.25rem;  /* 20px */
    --spacing-md: 1.5rem;   /* 24px */
    --spacing-lg: 2rem;     /* 32px */
    --spacing-xl: 3rem;     /* 48px */
  }
}
```

### 3.3 Margin/Padding Usage

**Consistent Spacing**:
```css
/* Card padding responsive */
.card {
  padding: 0.75rem;      /* xs */
}

@media (min-width: 768px) {
  .card {
    padding: 1.25rem;    /* md */
  }
}

@media (min-width: 1024px) {
  .card {
    padding: 1.5rem;     /* lg */
  }
}

/* Gap in grid responsive */
.grid {
  gap: 0.75rem;          /* xs */
}

@media (min-width: 768px) {
  .grid {
    gap: 1rem;           /* md */
  }
}

@media (min-width: 1024px) {
  .grid {
    gap: 1.5rem;         /* lg */
  }
}
```

---

## 4. RESPONSIVE TYPOGRAPHY SCALE

### 4.1 Fluid Typography Using `clamp()`

**Modern Approach** (CSS clamp function):

```css
h1 {
  font-size: clamp(
    24px,           /* minimum (mobile) */
    5vw,            /* preferred (viewport-relative) */
    42px            /* maximum (desktop) */
  );
}

h2 {
  font-size: clamp(18px, 4vw, 28px);
}

h3 {
  font-size: clamp(14px, 3vw, 20px);
}

body {
  font-size: clamp(13px, 2vw, 14px);
}

small {
  font-size: clamp(11px, 1.5vw, 12px);
}
```

### 4.2 Fixed Typography Scale Per Breakpoint

**Alternative Approach** (fixed values):

```css
/* Mobile */
h1 { font-size: 24px; }
h2 { font-size: 18px; }
h3 { font-size: 14px; }
body { font-size: 13px; }

/* Tablet */
@media (min-width: 768px) {
  h1 { font-size: 32px; }
  h2 { font-size: 22px; }
  h3 { font-size: 16px; }
  body { font-size: 13px; }
}

/* Desktop */
@media (min-width: 1024px) {
  h1 { font-size: 42px; }
  h2 { font-size: 28px; }
  h3 { font-size: 20px; }
  body { font-size: 14px; }
}
```

### 4.3 Line Height Adjustments

```css
/* Line height: tighter on mobile, looser on desktop */
p {
  line-height: 1.5;      /* Mobile: compact */
}

@media (min-width: 768px) {
  p {
    line-height: 1.6;    /* Tablet: normal */
  }
}

@media (min-width: 1024px) {
  p {
    line-height: 1.7;    /* Desktop: generous */
  }
}
```

---

## 5. RESPONSIVE COMPONENT PATTERNS

### 5.1 Navigation Responsive Patterns

**Pattern 1: Hidden on Mobile, Visible on Larger**
```css
.desktop-nav {
  display: none;         /* Hidden by default */
}

@media (min-width: 1024px) {
  .desktop-nav {
    display: block;      /* Visible on desktop */
  }
}

.mobile-nav {
  display: block;        /* Visible by default */
}

@media (min-width: 1024px) {
  .mobile-nav {
    display: none;       /* Hidden on desktop */
  }
}
```

**Pattern 2: Responsive Width Transition**
```css
.sidebar {
  width: 100%;           /* Mobile: full width */
  position: relative;
}

@media (min-width: 768px) {
  .sidebar {
    width: 280px;        /* Tablet/Desktop: fixed width */
    position: fixed;
  }
}

@media (min-width: 1024px) {
  .sidebar {
    position: relative;  /* Desktop: normal flow */
  }
}
```

### 5.2 Flex Layout Responsive Patterns

**Pattern 3: Column on Mobile, Row on Larger**
```css
.executor-panel__body {
  display: flex;
  flex-direction: column;  /* Mobile: stacked */
  gap: 1rem;
}

@media (min-width: 1024px) {
  .executor-panel__body {
    flex-direction: row;   /* Desktop: side-by-side */
  }
}

.executor-panel__form {
  width: 100%;            /* Mobile: full width */
}

@media (min-width: 1024px) {
  .executor-panel__form {
    width: 400px;         /* Desktop: fixed width */
    flex-shrink: 0;
  }
}

.executor-panel__output {
  flex: 1;
  min-height: 400px;
}
```

**Pattern 4: Wrap vs No-Wrap**
```css
.button-group {
  display: flex;
  flex-wrap: wrap;           /* Mobile: wrap buttons */
  gap: 0.5rem;
}

@media (min-width: 1024px) {
  .button-group {
    flex-wrap: nowrap;       /* Desktop: single line */
    gap: 1rem;
  }
}
```

### 5.3 Grid Layout Responsive Patterns

**Pattern 5: Responsive Grid Columns**
```css
.card-grid {
  display: grid;
  grid-template-columns: 1fr;     /* Mobile: 1 column */
  gap: 0.75rem;
}

@media (min-width: 480px) {
  .card-grid {
    grid-template-columns: repeat(2, 1fr);  /* Landscape: 2 cols */
  }
}

@media (min-width: 768px) {
  .card-grid {
    grid-template-columns: repeat(3, 1fr);  /* Tablet: 3 cols */
  }
}

@media (min-width: 1024px) {
  .card-grid {
    grid-template-columns: repeat(4, 1fr);  /* Desktop: 4 cols */
  }
}
```

**Pattern 6: Auto-Fill Responsive Grid**
```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
}
/* Automatically creates as many columns as fit within container */
/* Scales smoothly across all breakpoints */
```

### 5.4 Visibility Patterns

**Pattern 7: Show/Hide Based on Device**
```css
/* Mobile-only elements */
.mobile-only {
  display: block;
}

@media (min-width: 768px) {
  .mobile-only {
    display: none;
  }
}

/* Desktop-only elements */
.desktop-only {
  display: none;
}

@media (min-width: 1024px) {
  .desktop-only {
    display: block;
  }
}

/* Tablet-only */
.tablet-only {
  display: none;
}

@media (min-width: 768px) and (max-width: 1023px) {
  .tablet-only {
    display: block;
  }
}
```

---

## 6. RESPONSIVE SIZE SPECIFICATIONS

### 6.1 Component Dimensions

#### Header
```
┌─────────────────────────────────────┐
│ Mobile (xs)  │ Tablet (md) │ Desktop (lg)
├──────────────┼─────────────┼──────────────
│ Height: 48px │ 56px        │ 56px
│ Padding: 0.75rem          │ 1.25rem
│ Logo: 32px   │ 40px        │ 40px
└──────────────┴─────────────┴──────────────
```

**CSS**:
```css
.app-header {
  height: 48px;
  padding: 0 0.75rem;
}

@media (min-width: 768px) {
  .app-header {
    height: 56px;
    padding: 0 1.25rem;
  }
}

.app-header__logo-icon {
  width: 32px;
  height: 32px;
}

@media (min-width: 768px) {
  .app-header__logo-icon {
    width: 40px;
    height: 40px;
  }
}
```

#### Sidebar
```
Mobile (xs):     Hidden (offscreen)
Tablet (md):     70px (collapsed), 280px (expanded)
Desktop (lg):    280px (visible)
```

**CSS**:
```css
.sidebar {
  width: 70px;           /* Tablet: collapsed */
  transition: width 0.3s ease;
}

.sidebar--expanded {
  width: 280px;          /* Tablet: expanded */
}

@media (max-width: 767px) {
  .sidebar {
    position: fixed;
    left: 0;
    top: 0;
    height: 100vh;
    width: 280px;
    transform: translateX(-100%);  /* Hidden */
    z-index: 200;
  }

  .sidebar--open {
    transform: translateX(0);      /* Visible */
  }
}

@media (min-width: 1024px) {
  .sidebar {
    width: 280px;        /* Desktop: always visible */
    position: relative;
  }
}
```

#### Tab Bar (Mobile Only)
```
Height:      60px (fixed bottom)
Items:       5 (Home, Modules, Search, Settings, More)
Item Width:  20% (flex 1)
Gap:         Included in width
Safe Area:   +env(safe-area-inset-bottom)
```

**CSS**:
```css
.mobile-tab-bar {
  display: flex;
  height: 60px;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  padding-bottom: max(0, env(safe-area-inset-bottom));
  z-index: 150;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border);
}

.mobile-tab-bar__item {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  min-height: 44px;      /* Touch target */
}

@media (min-width: 768px) {
  .mobile-tab-bar {
    display: none;       /* Hidden on tablet+ */
  }
}
```

#### Status Bar
```
Height:      50px
Layout:      flex row, space-between
Items:       Left info, Center button, Right info
```

### 6.2 Card & Box Dimensions

**Module Card**:
```
Mobile (xs):     100% width
Mobile (sm):     50% width (2 cols)
Tablet (md):     calc(33.33% - 0.67rem)  /* 3 cols */
Desktop (lg):    auto-fill, minmax(320px, 1fr)
Min Height:      Auto (content-based)
Padding:         1rem (mobile), 1.25rem (tablet+)
Border Radius:   12px (all sizes)
```

**Stat Card Grid Item**:
```
Mobile (xs):     calc(50% - 0.375rem)    /* 2 cols */
Mobile (sm):     calc(50% - 0.375rem)    /* 2 cols */
Tablet (md):     calc(33.33% - 0.67rem)  /* 3 cols */
Desktop (lg):    calc(16.67% - 0.83rem)  /* 6 cols */
```

---

## 7. RESPONSIVE TOUCH & INTERACTION TARGETS

### 7.1 Minimum Touch Target Sizes

**Standard**: 44×44px (Apple, Google, WCAG)
**Recommended**: 48×48px
**Minimum**: 40×40px (acceptable in dense UIs)

```css
/* Buttons */
button {
  min-height: 44px;
  min-width: 44px;
  padding: 0.5rem 1rem;  /* Ensures minimum size */
}

/* Links */
a {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
}

/* Form controls */
input,
select,
textarea {
  min-height: 44px;
  padding: 0.65rem 0.75rem;
}

/* Checkboxes & Radios */
input[type="checkbox"],
input[type="radio"] {
  width: 20px;
  height: 20px;
  min-width: 20px;
  min-height: 20px;
  cursor: pointer;
}

/* Label should be clickable, combine with input */
label {
  display: flex;
  align-items: center;
  cursor: pointer;
  gap: 0.5rem;
  padding: 0.35rem;  /* Extra padding for click area */
}
```

### 7.2 Touch Feedback States

```css
/* Hover state: for devices that support hover */
@media (hover: hover) {
  button:hover {
    background: var(--bg-elevated);
  }
}

/* Touch state: for touch-only devices */
@media (hover: none) {
  button:active {
    background: var(--bg-elevated);
  }
}

/* Combined for compatibility */
button:hover,
button:active {
  background: var(--bg-elevated);
  transform: translateY(-1px);
}

button:active {
  transform: translateY(0);  /* Pressed state */
}
```

---

## 8. RESPONSIVE SAFE AREAS (Notch Handling)

### 8.1 Safe Area CSS

```css
/* For notched devices (iPhone X+, Android with notch) */
body {
  padding-left: max(1rem, env(safe-area-inset-left));
  padding-right: max(1rem, env(safe-area-inset-right));
  padding-top: max(0.5rem, env(safe-area-inset-top));
}

.app-header {
  padding-left: max(1rem, env(safe-area-inset-left));
  padding-right: max(1rem, env(safe-area-inset-right));
  padding-top: max(0.25rem, env(safe-area-inset-top));
}

.mobile-tab-bar {
  padding-bottom: max(0.5rem, env(safe-area-inset-bottom));
}

/* Fixed positioned elements */
.fixed-bottom {
  bottom: env(safe-area-inset-bottom);
  padding: 1rem max(1rem, env(safe-area-inset-left))
           env(safe-area-inset-bottom) max(1rem, env(safe-area-inset-right));
}
```

### 8.2 Viewport Meta Tag

```html
<meta 
  name="viewport" 
  content="width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=5.0, user-scalable=yes"
>
```

---

## 9. RESPONSIVE DISPLAY UTILITIES

### 9.1 Display Classes

```css
/* Hide on specific breakpoints */
.hide-mobile { display: none; }
@media (min-width: 768px) { .hide-mobile { display: block; } }

.hide-tablet { display: block; }
@media (min-width: 768px) and (max-width: 1023px) { .hide-tablet { display: none; } }

.hide-desktop { display: block; }
@media (min-width: 1024px) { .hide-desktop { display: none; } }

/* Show on specific breakpoints */
.show-mobile { display: block; }
@media (min-width: 768px) { .show-mobile { display: none; } }

.show-desktop { display: none; }
@media (min-width: 1024px) { .show-desktop { display: block; } }

/* Size-based display */
.display-flex-mobile { display: none; }
@media (max-width: 767px) { .display-flex-mobile { display: flex; } }

.display-grid-tablet { display: none; }
@media (min-width: 768px) { .display-grid-tablet { display: grid; } }
```

---

## 10. RESPONSIVE LAYOUT CHECKLIST

- [ ] All breakpoints defined (xs, sm, md, lg, xl)
- [ ] Mobile-first CSS approach used throughout
- [ ] No horizontal scrolling on any device
- [ ] Content visible without overlap
- [ ] Touch targets ≥44px on mobile
- [ ] Typography scales by breakpoint
- [ ] Spacing adjusts responsively
- [ ] Navigation adapts to viewport
- [ ] Forms responsive and functional
- [ ] Cards and grids adjust columns
- [ ] Images responsive (srcset, picture)
- [ ] Safe areas handled (notched devices)
- [ ] Tested on all target devices
- [ ] Performance acceptable on mobile

---

This specification document serves as the reference for implementing and maintaining responsive layouts throughout the JRTS application.
