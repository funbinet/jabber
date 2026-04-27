# JRTS Responsive UI Component Specifications
**Document Type**: Component Library Reference  
**Version**: 1.0  
**Purpose**: Detailed specifications for all responsive UI components

---

## OVERVIEW

This document defines the responsive specifications, visual states, and implementation details for all JRTS UI components. Each component includes responsive breakpoint behavior, CSS specifications, and usage patterns.

---

## TABLE OF CONTENTS

1. [Header Component](#header-component)
2. [Navigation Components](#navigation-components)
3. [Dashboard Components](#dashboard-components)
4. [Card Components](#card-components)
5. [Form Components](#form-components)
6. [Output & Display Components](#output--display-components)
7. [Terminal Component](#terminal-component)
8. [Footer/Status Bar](#footerstatus-bar)
9. [Utility Components](#utility-components)

---

## HEADER COMPONENT

### Specifications

**Variant**: Adaptive Header (All Devices)

**Responsive States**:

#### Mobile (xs-sm: 320-480px)
```
┌──────────────────────────────┐
│ ☰  JABBER           🟢 Online │
└──────────────────────────────┘
Height: 48px
Logo: Icon only (32×32px) + single word
Title: "JABBER" text
Status: Dot indicator only
Hamburger: Visible, left-aligned
Spacing: 0.75rem padding
```

#### Tablet (md: 768-1024px)
```
┌────────────────────────────────┐
│ ☰ [Icon] JABBER RT Suite  🟢 🔌 │
└────────────────────────────────┘
Height: 56px
Logo: Icon (40×40px) + abbreviated text
Title: "JABBER RT SUITE"
Status: Dot + connection indicator
Hamburger: Visible, toggles sidebar
Spacing: 1rem padding
```

#### Desktop (lg+: 1024px)
```
┌──────────────────────────────────────────────────┐
│ [Logo] JABBER RED TEAMING SUITE    🟢 Online ... │
│         (40×40px)                                 │
└──────────────────────────────────────────────────┘
Height: 56px
Logo: Icon (40×40px) visible
Title: Full "JABBER RED TEAMING SUITE"
Status: Dot + status text + version info
Hamburger: Hidden
Spacing: 1.25rem padding
```

### CSS Structure

```css
.app-header {
  display: flex;
  align-items: center;
  height: var(--header-height);
  background: var(--gradient-header);
  border-bottom: 1px solid var(--border);
  padding: 0 var(--header-padding);
  gap: 1rem;
  z-index: 100;
  backdrop-filter: blur(12px);
  -webkit-app-region: drag;
}

/* Mobile defaults */
.app-header {
  height: 48px;
  --header-padding: 0.75rem;
}

/* Tablet and up */
@media (min-width: 768px) {
  .app-header {
    height: 56px;
    --header-padding: 1.25rem;
  }
}

/* Header sections */
.app-header__logo {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  -webkit-app-region: no-drag;
}

.app-header__logo-icon {
  width: 32px;
  height: 32px;
  flex-shrink: 0;
}

@media (min-width: 768px) {
  .app-header__logo-icon {
    width: 40px;
    height: 40px;
  }
}

.app-header__title {
  font-size: 14px;
  font-weight: 700;
  color: white;
  -webkit-app-region: no-drag;
}

@media (min-width: 768px) {
  .app-header__title {
    font-size: 16px;
  }
}

.app-header__title-full {
  display: none;
}

@media (min-width: 1024px) {
  .app-header__title-full {
    display: block;
  }
}

.app-header__title-abbr {
  display: block;
}

@media (min-width: 1024px) {
  .app-header__title-abbr {
    display: none;
  }
}

.app-header__spacer {
  flex: 1;
}

.app-header__status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 12px;
  color: var(--steel);
}

/* Hide status details on mobile */
.app-header__status-details {
  display: none;
}

@media (min-width: 1024px) {
  .app-header__status-details {
    display: inline;
    border-left: 1px solid var(--border);
    padding-left: 0.75rem;
    margin-left: 0.25rem;
  }
}

.app-header__menu-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  background: transparent;
  border: none;
  color: var(--steel);
  cursor: pointer;
  border-radius: var(--radius-sm);
  transition: all var(--transition-fast);
  -webkit-app-region: no-drag;
}

.app-header__menu-toggle:hover {
  color: var(--steel-light);
  background: var(--bg-tertiary);
}

@media (min-width: 1024px) {
  .app-header__menu-toggle {
    display: none;
  }
}
```

### Animated States

**Scroll Behavior** (Optional enhancement):
```css
.app-header--scrolled {
  background: rgba(13, 17, 23, 0.95);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
```

---

## NAVIGATION COMPONENTS

### 1. Sidebar Navigation

**Variant**: Adaptive Sidebar (Tablet & Desktop)

#### Desktop (lg+: 1024px)
```
┌──────────────────────────┐
│ [LOGO]  (70×70 px)       │
│                          │
│ INTELLIGENCE & PLANNING  │
│ • Reconnaissance         │
│ • Vulnerability Scan     │
│ • Social Engineering     │
│                          │
│ ACCESS & PENETRATION     │
│ • Exploitation           │
│ • Web Assessment         │
│ • [More items...]        │
│                          │
├──────────────────────────┤
│ [USER PROFILE]           │ (70×70 px)
│ Account Settings         │
└──────────────────────────┘

Width: 280px (fixed)
Position: Relative
Scroll: Independent overflow-y
Logo Section: 70px height
Item height: 36px
Footer section: 70px height
```

#### Tablet (md: 768-1024px) - Collapsed Default
```
┌────────┐
│ [LOGO] │ 70px width
│        │
│ [I]    │ Home icon
│ [I]    │ Module icon
│ [I]    │ Others...
│ [I]    │
│        │
├────────┤
│[USERP] │ 70px user profile
└────────┘

Width: 70px (default)
Position: Fixed left
Expand on: Hover or explicit interaction
Expanded Width: 280px (slide out)
Logo Section: Icon only (70×70 px)
Item display: Icon + tooltip
Footer: Icon only
```

#### Mobile (xs-sm) - Hidden
```
Hidden by default
Slides in from left on menu open
Position: Fixed, full height
Width: 280px
Z-index: 200 (above content)
Overlay: Semi-transparent backdrop
```

### 2. Mobile Tab Bar

**Variant**: Bottom Tab Navigation (Mobile Only)

#### Mobile (xs-sm: 320-480px)
```
┌────────────────────────────┐
│ 🏠    📦    🔍    ⚙️    ⋮  │
│HOME  MOD  SEARCH SETTING MORE
└────────────────────────────┘

Position: Fixed bottom, full width
Height: 60px + safe area padding
Items: 5 maximum
Layout: Flex, space-around
Touchable Height: 44px per item
Background: var(--bg-secondary)
Border: 1px top border

Active State:
  background: var(--crimson)
  color: white
  
Inactive State:
  color: var(--steel)
  
Hover/Active (touch):
  color: var(--steel-light)
```

### CSS for Navigation

```css
/* Sidebar */
.sidebar {
  width: 70px;
  background: var(--gradient-sidebar);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  flex-shrink: 0;
  padding: 0.75rem 0;
  transition: width var(--transition-normal);
  position: relative;
}

@media (max-width: 767px) {
  .sidebar {
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    width: 280px;
    height: 100vh;
    transform: translateX(-100%);
    z-index: 200;
    transition: transform var(--transition-normal);
  }

  .sidebar--open {
    transform: translateX(0);
  }
}

@media (min-width: 1024px) {
  .sidebar {
    width: 280px;
    position: relative;
    transform: translateX(0);
  }
}

.sidebar__item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1.25rem;
  cursor: pointer;
  transition: all var(--transition-fast);
  border-left: 3px solid transparent;
  font-size: 13px;
  color: var(--steel);
}

@media (max-width: 1023px) {
  .sidebar__item {
    padding: 0.5rem 1.25rem;
    justify-content: center;
  }
}

.sidebar__item-label {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (max-width: 1023px) {
  .sidebar__item-label {
    display: none;
  }
}

.sidebar:hover .sidebar__item-label,
.sidebar--expanded .sidebar__item-label {
  display: inline;
}

.sidebar__item:hover {
  color: var(--steel-light);
  border-left-color: var(--crimson);
}

.sidebar__item--active {
  color: white;
  border-left-color: var(--crimson);
  background: var(--bg-tertiary);
}

/* Mobile Tab Bar */
.mobile-tab-bar {
  display: none;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  height: 60px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border);
  z-index: 150;
  padding-bottom: max(0, env(safe-area-inset-bottom));
  box-sizing: border-box;
}

@media (max-width: 767px) {
  .mobile-tab-bar {
    display: flex;
  }
}

.mobile-tab-bar__item {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.25rem;
  cursor: pointer;
  transition: all var(--transition-fast);
  color: var(--steel);
  text-decoration: none;
  border-bottom: 3px solid transparent;
  min-height: 44px;
}

.mobile-tab-bar__item:active {
  color: var(--steel-light);
}

.mobile-tab-bar__item--active {
  background: var(--crimson);
  color: white;
  border-bottom-color: var(--crimson);
}

.mobile-tab-bar__item-icon {
  font-size: 20px;
}

.mobile-tab-bar__item-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
```

---

## DASHBOARD COMPONENTS

### 1. Dashboard Hero Section

```
┌────────────────────────────────────────────┐
│                                            │
│            JABBER                          │
│        Red Teaming Suite V3.5              │
│                                            │
│  Engine online with 150 native modules    │
│  across 12 active categories...           │
│                                            │
└────────────────────────────────────────────┘
```

**Responsive Specifications**:

| Breakpoint | Padding | Title Size | Subtitle Size | Content Width |
|------------|---------|------------|---------------|---------------|
| Mobile (xs) | 2rem 1rem | 24px | 14px | 100% |
| Tablet (md) | 2.5rem 1.5rem | 32px | 15px | 90% |
| Desktop (lg) | 3rem 2rem | 42px | 16px | 600px max |

**CSS**:
```css
.dashboard-home__hero {
  text-align: center;
  padding: 2rem 1rem;
  background: var(--gradient-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  position: relative;
  overflow: hidden;
  margin-bottom: 2rem;
}

@media (min-width: 768px) {
  .dashboard-home__hero {
    padding: 2.5rem 1.5rem;
  }
}

@media (min-width: 1024px) {
  .dashboard-home__hero {
    padding: 3rem 2rem;
  }
}

.dashboard-home__hero h1 {
  font-size: clamp(24px, 5vw, 42px);
  background: linear-gradient(135deg, #ff4444 0%, #ff8888 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 0.5rem;
  letter-spacing: -0.5px;
}

.dashboard-home__hero h2 {
  font-size: clamp(14px, 3vw, 16px);
  color: var(--steel);
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 1rem;
}

.dashboard-home__hero p {
  color: var(--steel);
  font-size: clamp(12px, 2vw, 13px);
  max-width: 600px;
  margin: 0 auto;
  line-height: 1.7;
}
```

### 2. Stats Bar Component

**Mobile (xs-sm)**:
```
┌────────────────────────────────┐
│ ┌──────────┬──────────────┐    │
│ │ 🧩 150   │ 📊 12        │    │
│ │ Modules  │ Categories   │    │
│ ├──────────┼──────────────┤    │
│ │ ⚡ 4     │ 🛡️ 10        │    │
│ │ Critical │ High Risk    │    │
│ ├──────────┼──────────────┤    │
│ │ 🎯 8     │ 📈 19        │    │
│ │ Medium   │ Categories   │    │
│ └──────────┴──────────────┘    │
└────────────────────────────────┘
Grid: 2 columns
Gap: 0.75rem
Card Padding: 1rem
```

**Tablet (md)**:
```
┌──────────────────────────────────────────────┐
│ ┌──────┬──────┬──────┐                       │
│ │ 🧩   │ 📊   │ ⚡   │                       │
│ │ 150  │ 12   │ 4    │                       │
│ │ Mods │ Cat  │ Crit │                       │
│ ├──────┼──────┼──────┤                       │
│ │ 🛡️   │ 🎯   │ 📈   │                       │
│ │ 10   │ 8    │ 19   │                       │
│ │ High │ Med  │ Tot  │                       │
│ └──────┴──────┴──────┘                       │
└──────────────────────────────────────────────┘
Grid: 3 columns
Gap: 1rem
```

**Desktop (lg+)**:
```
┌───────────────────────────────────────────────────────────┐
│ ┌────┬────┬────┬────┬────┬────┐                           │
│ │🧩  │📊 │⚡  │🛡️  │🎯  │📈  │                           │
│ │150 │12 │4   │10  │8   │19  │ (all in single row)      │
│ │Mods│Cat│Crit│High│Med│Tot │                           │
│ └────┴────┴────┴────┴────┴────┘                           │
└───────────────────────────────────────────────────────────┘
Grid: 6 columns
Gap: 1rem
Card Padding: 1.25rem (desktop), 1rem (tablet)
```

**CSS**:
```css
.dashboard-home__stats {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
}

@media (min-width: 768px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    padding: 1.25rem;
  }
}

@media (min-width: 1024px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(6, 1fr);
  }
}

.stat-card {
  background: var(--gradient-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 1rem;
  text-align: center;
  transition: all var(--transition-normal);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.stat-card:hover {
  border-color: var(--crimson);
  transform: translateY(-2px);
  box-shadow: var(--shadow-glow-crimson);
}

.stat-card__value {
  font-size: clamp(20px, 4vw, 32px);
  font-weight: 800;
  color: var(--crimson);
}

.stat-card__label {
  font-size: 11px;
  color: var(--steel);
  text-transform: uppercase;
  letter-spacing: 1px;
}
```

---

## CARD COMPONENTS

### Module Card Specification

**Responsive Dimensions**:

| Breakpoint | Width | Columns | Min-Height | Padding |
|------------|-------|---------|------------|---------|
| Mobile (xs) | 100% | 1 | auto | 1rem |
| Mobile (sm) | calc(50% - 0.375rem) | 2 | 280px | 1rem |
| Tablet (md) | calc(33.33% - 0.67rem) | 3 | 300px | 1.25rem |
| Desktop (lg) | minmax(320px, 1fr) | auto | 300px | 1.25rem |

**Visual Structure**:
```
┌────────────────────────────┐
│ Module Name      [CRITICAL] │  H: 20px (name row)
├────────────────────────────┤
│ Short description text      │  H: 60px (3 lines max)
│ wrapped to 3 lines max..    │
├────────────────────────────┤
│ v1.2.3  @source/ref         │  H: 18px (meta row)
└────────────────────────────┘

Total Min Height: 280px (flexible)
Border: 1px solid --border
Border Radius: 12px
Padding: varies by breakpoint
Gap between sections: 0.75rem
```

**CSS Structure**:
```css
.module-card {
  background: var(--gradient-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 1rem;
  cursor: pointer;
  transition: all var(--transition-normal);
  display: flex;
  flex-direction: column;
  min-height: auto;
  backdrop-filter: blur(8px);
}

@media (min-width: 480px) {
  .module-card {
    min-height: 280px;
  }
}

@media (min-width: 768px) {
  .module-card {
    padding: 1.25rem;
    min-height: 300px;
  }
}

.module-card:hover {
  border-color: var(--crimson);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg), var(--shadow-glow-crimson);
}

.module-card__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 0.75rem;
  gap: 0.5rem;
}

.module-card__name {
  font-size: clamp(13px, 3vw, 15px);
  font-weight: 700;
  color: white;
  line-height: 1.3;
  flex: 1;
}

.module-card__risk {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  white-space: nowrap;
  flex-shrink: 0;
}

.module-card__description {
  font-size: clamp(11px, 2vw, 12px);
  color: var(--steel);
  line-height: 1.6;
  margin-bottom: 0.75rem;
  flex: 1;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.module-card__meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: clamp(10px, 1.5vw, 11px);
  color: var(--steel);
  flex-wrap: wrap;
  margin-top: auto;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border);
}
```

---

## FORM COMPONENTS

### Form Layout (Responsive Design)

**Mobile (xs-sm)**:
```
┌─────────────────────┐
│ FIELD LABEL         │
│ [Input : 100%]      │
│ Help text           │
│                     │
│ MODE SELECTOR       │
│ ┌──┬──┬──┐          │
│ │A │B │C │ (stack) │
│ └──┴──┴──┘          │
│                     │
│ TARGET HOSTS        │
│ [Textarea : 100%]   │
│ (multiline)         │
│                     │
│ [EXECUTE : 100%]    │
│ (full-width button) │
└─────────────────────┘
Single column, stacked
Field width: 100%
Button width: 100%
Min touch height: 44px
```

**Tablet/Desktop (md+)**:
```
┌────────────────────────────────┐
│ FIELD LABEL   | FIELD LABEL    │
│ [Input: 48%]  | [Input: 48%]   │
│               |                │
│ MODE SELECTOR (full width)     │
│ ┌──┬──┬──┐ (horizontal)        │
│ │A │B │C │                     │
│ └──┴──┴──┘                     │
│                                │
│ TARGET HOSTS (full width)      │
│ [Textarea: 100%]               │
│                                │
│ [EXECUTE] [RESET] [HELP]       │
│ (buttons row)                  │
└────────────────────────────────┘
Two columns for simple fields
Full-width for complex controls
Button row with gap
```

**Form Field Specifications**:
```
Input/Select Height:  44px (mobile), 40px (desktop)
Font Size:            16px (mobile, prevents zoom)
                      14px (desktop)
Padding:              0.65rem 0.75rem (mobile)
                      0.5rem 0.75rem (desktop)
Border:               1px solid --border
Border Radius:        var(--radius-sm) = 4px
Background:           var(--bg-input)
Focus Border:         var(--border-focus)
Focus Shadow:         0 0 0 2px rgba(88, 166, 255, 0.15)
```

**CSS**:
```css
.form-group {
  margin-bottom: 1rem;
}

.form-group__label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: var(--steel-light);
  margin-bottom: 0.35rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.form-group__input,
.form-group__select,
.form-group__textarea {
  width: 100%;
  padding: 0.65rem 0.75rem;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--steel-light);
  font-family: var(--font-primary);
  font-size: 16px;
  transition: border-color var(--transition-fast);
  outline: none;
  min-height: 44px;
}

@media (min-width: 768px) {
  .form-group__input,
  .form-group__select,
  .form-group__textarea {
    font-size: 14px;
    padding: 0.5rem 0.75rem;
    min-height: 40px;
  }
}

.form-group__input:focus,
.form-group__select:focus,
.form-group__textarea:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.15);
}

/* Mode segmented control */
.mode-segmented {
  display: grid;
  width: 100%;
  grid-template-columns: repeat(auto-fit, minmax(60px, 1fr));
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-input);
  overflow: hidden;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02);
}

.mode-segmented__segment {
  border: none;
  border-right: 1px solid var(--border);
  background: transparent;
  color: var(--steel);
  font-family: var(--font-primary);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  padding: 0.55rem;
  cursor: pointer;
  transition: all var(--transition-fast);
  min-height: 40px;
}

.mode-segmented__segment:last-child {
  border-right: none;
}

.mode-segmented__segment--active {
  color: white;
  background: linear-gradient(180deg, rgba(248, 81, 73, 0.18) 0%, rgba(248, 81, 73, 0.12) 100%);
  box-shadow: inset 0 -2px 0 0 var(--crimson);
}

/* Button group */
.button-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

@media (min-width: 768px) {
  .button-group {
    flex-wrap: nowrap;
    gap: 1rem;
  }
}
```

---

## OUTPUT & DISPLAY COMPONENTS

### Output Renderer (Multi-Format)

**Responsive Layout**:

**Mobile (xs-sm)**:
```
┌────────────────────────────┐
│ FORMAT TOGGLE (vertical)   │ H: auto
│ ┌───────────────────────┐  │
│ │ [JSON]                │  │
│ │ [HTML]                │  │
│ │ [MARKDOWN]            │  │
│ │ [RAW]                 │  │
│ └───────────────────────┘  │
├────────────────────────────┤
│ CONTENT AREA (scrollable)  │ H: 400px
│                            │
│ [JSON/HTML/MD content]     │
│                            │
├────────────────────────────┤
│ CONTROLS (vertical stack)  │ H: auto
│ ┌───────────────────────┐  │
│ │ 📥 SAVE               │  │
│ │ 📤 DOWNLOAD           │  │
│ │ ⛶ FULLSCREEN          │  │
│ │ 🗑 CLEAR              │  │
│ └───────────────────────┘  │
└────────────────────────────┘
```

**Tablet/Desktop (md+)**:
```
┌───────────────────────────────────┐
│ [JSON] [HTML] [MARKDOWN] [RAW]    │  H: 32px
├───────────────────────────────────┤
│ CONTENT AREA (scrollable)         │  H: 500px
│ JSON/HTML/MD rendering            │
│ [Syntax highlighting / rendering] │
│                                   │
│                                   │
├───────────────────────────────────┤
│ 📥 SAVE  📤 DOWNLOAD ⛶ FULLSCREEN 🗑│ H: 36px
└───────────────────────────────────┘
Format selector: Horizontal
Controls: Horizontal row
```

**CSS**:
```css
.output-renderer {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 400px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.output-renderer__toolbar {
  display: flex;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
  flex-direction: column;
}

@media (min-width: 768px) {
  .output-renderer__toolbar {
    flex-direction: row;
    flex-wrap: nowrap;
  }
}

.output-renderer__format-toggle {
  display: flex;
  gap: 0.25rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-input);
  padding: 2px;
  width: 100%;
  flex-wrap: wrap;
}

@media (min-width: 768px) {
  .output-renderer__format-toggle {
    width: auto;
    flex-wrap: nowrap;
  }
}

.output-renderer__format-btn {
  padding: 0.35rem 0.75rem;
  border: none;
  background: transparent;
  color: var(--steel);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  cursor: pointer;
  border-radius: 3px;
  transition: all var(--transition-fast);
  min-height: 32px;
  flex: 1;
}

@media (min-width: 768px) {
  .output-renderer__format-btn {
    flex: 0 1 auto;
  }
}

.output-renderer__format-btn--active {
  background: var(--crimson);
  color: white;
}

.output-renderer__content {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.5;
  color: var(--steel-light);
  white-space: pre-wrap;
  word-break: break-word;
}

.output-renderer__controls {
  display: flex;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  border-top: 1px solid var(--border);
  flex-wrap: wrap;
  flex-direction: column;
}

@media (min-width: 768px) {
  .output-renderer__controls {
    flex-direction: row;
    flex-wrap: nowrap;
  }
}

.output-renderer__control-btn {
  padding: 0.5rem 1rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  color: var(--steel);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  min-height: 36px;
  flex: 1;
  justify-content: center;
}

@media (min-width: 768px) {
  .output-renderer__control-btn {
    flex: 0 1 auto;
  }
}

.output-renderer__control-btn:hover {
  border-color: var(--crimson);
  color: var(--crimson);
}
```

---

## TERMINAL COMPONENT

### Terminal Responsive Positioning

**Mobile (xs-sm)**:
```
Fullscreen Overlay
Position: Fixed, covers 100% viewport
Width: 100vw
Height: 100vh - safe area
Close Button: Top-right corner (36×36px)
Content: xterm.js terminal
Controls: Minimized header only
```

**Tablet (md)**:
```
Slide-up Modal
Position: Fixed bottom
Height: 60-70% viewport
Width: 100% - safe area margins
Close/Minimize: Top-right
Drag resize: Top edge
Overlay: Semi-transparent background
```

**Desktop (lg+)**:
```
Side or Bottom Panel
Position: Relative within layout
Height: 300-400px adjustable
Width: 100% of workspace
Resize: Top edge draggable
Toggle: Via statusbar button
No overlay (part of layout)
```

---

## FOOTER/STATUS BAR

### Status Bar Responsive Design

**Mobile (xs-sm)**:
```
┌────────────────────────────┐
│ 🔗 dancan.tech            │ Row 1: Creator info
├────────────────────────────┤
│ [TERMINAL] []  [Connected]│ Row 2: Status
└────────────────────────────┘
Height: Auto (wrapping)
Layout: Flex column wrap
Creator: Full name
Links: Icon row
Terminal: Full-width button
Status: Right-aligned
```

**Tablet/Desktop (md+)**:
```
┌──────────────────────────────────────────┐
│ 🔗dancan.tech [links] │ [TERMINAL] │ ..│
└──────────────────────────────────────────┘
Height: 50px fixed
Layout: Flex row space-between
Creator: Full name visible
Links: Icon set
Terminal: Button in center
Status: Right side, full details
```

**CSS**:
```css
.statusbar {
  height: var(--statusbar-height);
  background: var(--bg-secondary);
  border-top: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 1rem;
  font-size: 11px;
  color: var(--steel);
  z-index: 100;
  flex-wrap: wrap;
}

.statusbar__left,
.statusbar__center,
.statusbar__right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

@media (max-width: 767px) {
  .statusbar__center {
    flex-basis: 100%;
    margin: 0.5rem 0;
    justify-content: center;
  }
}
```

---

## UTILITY COMPONENTS

### Button Specifications

**Sizes**:
```
Compact:  h: 32px  px: 0.75rem  f: 11px
Normal:   h: 40px  px: 1rem     f: 12px
Large:    h: 44px  px: 1.25rem  f: 13px (mobile touch)
```

**Variants**:
```
Primary:   crimson gradient, white text, shadow
Secondary: tertiary bg, border, light text
Ghost:     transparent, steel text
Danger:    red accent for destructive actions
Disabled:  50% opacity, no cursor
```

### Badge Specifications

**Risk Level Badges**:
```
LOW:      green bg (3fb95020), green text (3fb950)
MEDIUM:   amber bg (d2992220), amber text (d29922)
HIGH:     orange bg (f0883e20), orange text (f0883e)
CRITICAL: red bg (f8514920), red/crimson text
```

**Size Variants**:
```
Small:     h: 20px  px: 6px  f: 10px
Normal:    h: 24px  px: 8px  f: 11px
Large:     h: 28px  px: 10px f: 12px
```

---

## RESPONSIVE ANIMATION SPECIFICATIONS

### Transitions

```css
/* Fast feedback (hover, click) */
--transition-fast: 150ms ease;

/* Standard navigation & state changes */
--transition-normal: 300ms ease;

/* Significant layout changes */
--transition-slow: 500ms ease;
```

### Animations

**Fade In**:
```css
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

.animate-fade-in {
  animation: fadeIn var(--transition-normal) ease forwards;
}
```

**Slide In**:
```css
@keyframes slideInLeft {
  from { opacity: 0; transform: translateX(-16px); }
  to { opacity: 1; transform: translateX(0); }
}

.animate-slide-in {
  animation: slideInLeft var(--transition-normal) ease forwards;
}
```

**Mobile Animation Considerations**:
```css
/* Respect reduced motion preference */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

/* Optimize for mobile */
@media (max-width: 767px) {
  /* Keep animations short on mobile */
  --transition-normal: 200ms ease;
  
  /* Disable expensive animations */
  .expensive-animation {
    animation: none !important;
  }
}
```

---

## ACCESSIBILITY SPECIFICATIONS

### Focus Indicators

```css
*:focus-visible {
  outline: 2px solid var(--ice-blue);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

/* Higher contrast on mobile */
@media (hover: none) {
  *:focus-visible {
    outline: 3px solid var(--ice-blue);
    outline-offset: 3px;
  }
}
```

### Touch Target Minimum

```css
button,
a,
input[type="checkbox"],
input[type="radio"] {
  min-height: 44px;
  min-width: 44px;
}

/* Extra padding for safety zones */
@media (hover: none) {
  button,
  a {
    padding: 0.7rem 1.2rem;
  }
}
```

---

This comprehensive component specification document provides detailed responsive design requirements for all JRTS UI components across all device sizes.
