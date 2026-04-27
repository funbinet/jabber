# JRTS - Complete Responsive Architecture Implementation Plan
**Version**: 1.0  
**Date**: April 2026  
**Scope**: Mobile-first responsive redesign with device-agnostic rendering  
**Target Devices**: Mobile (320-480px) | Tablet (768-1024px) | Desktop (1024px+)

---

## EXECUTIVE SUMMARY

This document defines a comprehensive, reusable responsive architecture for the JRTS (Jabber Red Teaming Suite) UI. The transformation enables flawless rendering across all device sizes through a structured mobile-first approach, modular component design, and unified layout system. The implementation preserves existing functionality while introducing new responsive patterns that can be applied consistently across all modules.

**Key Outcomes**:
- Mobile-optimized interface with bottom tab bar navigation
- Tablet-responsive sidebar with toggle behavior
- Desktop-enhanced layout with advanced layouts
- Unified output rendering system (JSON/HTML/Markdown/Raw)
- Consistent design tokens and spacing system
- Reusable responsive component patterns

---

## PART 1: CURRENT STATE ANALYSIS

### 1.1 Existing Architecture Overview

**Technology Stack**:
- React 19.2.5 (Functional components, Hooks)
- Vite 8.0.8 (Build system)
- Electron 41.2.1 (Desktop runtime)
- CSS3 (Custom properties, Grid, Flexbox)
- Lucide React 1.8.0 (Icon system)
- xterm.js 6.0.0 (Terminal emulation)

**Component Structure**:
```
App.jsx (Root state & view management)
├── Header.jsx (Fixed top navbar)
├── Workspace.jsx (Content router/switch)
│   ├── DashboardHome.jsx (Landing page)
│   ├── ModuleGrid.jsx (Category modules)
│   ├── ModuleExecutor.jsx (Form + output)
│   ├── DeviceEnumeratorExecutor.jsx (Specialized)
│   ├── ReportManager.jsx (Report listing)
│   └── TargetProfiler.jsx (Analysis tool)
├── SideNav.jsx (Fixed left navigation)
├── StatusBar.jsx (Fixed bottom status)
└── InteractiveTerminal.jsx (Overlay terminal)
```

**Styling Approach**:
- Single `index.css` file (~1200 lines)
- CSS custom properties (--bg-primary, --crimson, etc.)
- Minimal responsive queries (only basic 768px breakpoint)
- Accent colors: Crimson (#ff4444), Emerald (#00ff41), Steel (#8b949e)
- Typography: Inter (UI) + JetBrains Mono (code)
- No CSS-in-JS framework (vanilla CSS)

**Current Limitations**:
- Desktop-centric layout assumptions
- Fixed sidebar (280px) not resizable on small screens
- No mobile navigation pattern
- Header doesn't adapt to small viewports
- Module cards not optimized for touch
- Output rendering assumes wide display
- Terminal overlay blocks most content on mobile
- Form layouts don't stack on small screens
- No responsive typography scaling

### 1.2 Design System Audit

**Color Tokens** (Define in CSS variables):
```css
/* Backgrounds */
--bg-primary: #0d1117        /* Main background */
--bg-secondary: #161b22      /* Secondary panels */
--bg-tertiary: #21262d       /* Tertiary elements */
--bg-elevated: #1c2333       /* Elevated surfaces */
--bg-card: #161b2280         /* Card backgrounds */

/* Accents - Risk/Status */
--crimson: #ff4444           /* Primary accent, errors */
--emerald: #00ff41           /* Success, online status */
--ice-blue: #58a6ff          /* Info, links */
--amber: #d29922             /* Warnings */
--risk-low: #3fb950          /* Low risk indicator */
--risk-medium: #d29922       /* Medium risk */
--risk-high: #f0883e         /* High risk */
--risk-critical: #f85149     /* Critical risk */
```

**Typography System** (Define responsive scales):
```
Headings: Inter, Bold/ExtraBold
  h1: 42px (desktop) | 28px (tablet) | 24px (mobile)
  h2: 28px (desktop) | 22px (tablet) | 18px (mobile)
  h3: 20px (desktop) | 16px (tablet) | 14px (mobile)

Body: Inter, Regular
  Base: 14px (desktop/tablet), 13px (mobile)
  Large: 16px, Normal: 14px, Small: 12px, Tiny: 10px

Mono: JetBrains Mono
  Code: 12px, Terminal: 12px, UI: 11px
```

**Spacing System** (8px base):
```
Base unit: 8px (1rem = 14px)
Padding/Margins: 0.5rem (4px), 1rem (8px), 1.5rem (12px), 2rem (16px), 3rem (24px)
Gap: 0.5rem, 0.75rem, 1rem, 1.5rem, 2rem
Borders: 1px, 2px
Corner radius: 4px (sm), 8px (md), 12px (lg), 16px (xl), 24px (xxl)
```

**Component Dimensions**:
```
Header: 56px height (desktop), 48px (mobile)
Sidebar: 280px width (desktop), 70px collapsed, 100vw mobile
Tab Bar: 60px height (mobile only)
Status Bar: 50px height
Card minimum: 320px width (mobile), expands to fill
Touch targets: 44px minimum height/width
```

---

## PART 2: RESPONSIVE LAYOUT SYSTEM

### 2.1 Breakpoint Strategy

**Defined Breakpoints**:
```css
/* Mobile First Approach */
xs: 320px   /* Extra small phones */
sm: 480px   /* Small phones & landscape */
md: 768px   /* Tablets portrait */
lg: 1024px  /* Tablets landscape & small desktop */
xl: 1440px  /* Full desktop & large displays */

/* Implementation */
@media (min-width: 480px) { /* sm and up */ }
@media (min-width: 768px) { /* md and up */ }
@media (min-width: 1024px) { /* lg and up */ }
@media (min-width: 1440px) { /* xl and up */ }
```

**Device Classes**:
```javascript
// Context provider will determine:
isMobile:   viewport < 768px    (portrait phones, landscape phones)
isTablet:   768px ≤ viewport < 1024px (tablets)
isDesktop:  viewport ≥ 1024px   (desktop, large displays)
```

### 2.2 Viewport Handling

**Responsive Meta Tag** (in index.html):
```html
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=5.0, user-scalable=yes">
```

**Container Queries** (Future enhancement):
```css
@container (min-width: 600px) {
  .card { grid-template-columns: repeat(2, 1fr); }
}
```

### 2.3 Layout Flex System

**Safe Areas** (for notched devices):
```css
padding-left: max(1rem, env(safe-area-inset-left));
padding-right: max(1rem, env(safe-area-inset-right));
padding-bottom: max(1rem, env(safe-area-inset-bottom));
padding-top: max(0.5rem, env(safe-area-inset-top));
```

**Main App Layout**:
```
Mobile (xs-sm):
┌─────────────────────┐
│ HEADER (48px)       │ (hamburger menu, minimal logo)
├─────────────────────┤
│                     │
│  WORKSPACE CONTENT  │
│  (scrollable)       │
│                     │
├─────────────────────┤
│ TAB BAR (60px)      │ (home, modules, search, settings, more)
└─────────────────────┘

Tablet (md):
┌─────────────────┬──────────────────┐
│ HEADER (56px)   │ (logo, hamburger)│
├─────────────────┼──────────────────┤
│ SIDEBAR (70px)  │ WORKSPACE        │
│ collapsed       │                  │
│                 │  (scrollable)    │
│                 │                  │
├─────────────────┴──────────────────┤
│ STATUS BAR (50px)                  │
└────────────────────────────────────┘

Desktop (lg+):
┌─────────────────┬──────────────────┐
│ HEADER (56px)   │ (logo, title)    │
├─────────────────┼──────────────────┤
│ SIDEBAR (280px) │ WORKSPACE        │
│ expanded        │                  │
│                 │  (scrollable)    │
│                 │                  │
├─────────────────┴──────────────────┤
│ STATUS BAR (50px)                  │
└────────────────────────────────────┘
```

### 2.4 Scrolling Behavior

**Implementation Strategy**:
```css
/* Root containers */
html, body, #root: height 100%, overflow hidden

/* Scrollable areas */
.workspace: flex 1, overflow-y auto
.sidebar: overflow-y auto (independently scrollable)
.terminal: overflow-y auto (within container)
.module-form: overflow-y auto (within panel)

/* Smooth scrolling */
scroll-behavior: smooth;
scroll-padding-top: var(--header-height);
```

**iOS Safari Fixes**:
```css
.scrollable {
  -webkit-overflow-scrolling: touch;
  position: relative;
  overflow-y: auto;
}
```

### 2.5 Safe Overlay Handling

**Terminal Modal**:
- Mobile: Full-screen overlay with close button
- Tablet: 70% viewport with drag-to-resize
- Desktop: Slide-up panel from bottom

**Fullscreen Output**:
- Canvas: vmax(100vh, 100vw) minus safe areas
- Controls: Fixed top-right with close button
- Revert: Returns to previous container

---

## PART 3: FILE-LEVEL MODIFICATION MAP

### 3.1 CSS Architecture Refactor

**Current State**: Single monolithic `src/index.css` (~1200 lines)

**Target State**: Modular CSS structure

```
src/styles/
├── index.css                 (Main imports, initialization)
├── tokens.css                (CSS variables, typography scales, spacing)
├── reset.css                 (Normalize, base element styles)
├── base.css                  (Global utilities, common patterns)
├── layout/
│   ├── app.css              (App container, flex structure)
│   ├── header.css            (Header styles, responsive)
│   ├── sidebar.css           (Sidebar & mobile nav)
│   ├── workspace.css         (Main content area)
│   ├── tabbar.css            (Mobile bottom tab bar)
│   └── responsive.css        (All breakpoints, media queries)
├── components/
│   ├── cards.css             (Module cards, stat cards)
│   ├── buttons.css           (Button variants, states)
│   ├── forms.css             (Inputs, selects, groups)
│   ├── badges.css            (Risk levels, status)
│   └── modals.css            (Dialogs, overlays)
├── pages/
│   ├── dashboard.css         (Dashboard layout, hero)
│   ├── modules.css           (Module grid layout)
│   ├── executor.css          (Executor panel layout)
│   ├── output.css            (Output panels, rendering)
│   └── terminal.css          (Terminal styles)
├── footer.css                (Status bar, footer)
└── animations.css            (Keyframes, transitions)
```

**Migration Strategy**:
1. Extract tokens → tokens.css
2. Extract reset → reset.css
3. Create layout/*.css files
4. Create components/*.css files
5. Create pages/*.css files
6. Update index.css with @import statements (preserve order)
7. Update HTML to import only src/styles/index.css

### 3.2 Component File Modifications

**Files to Modify** (with scope of changes):

#### Core Layout Components

**1. src/App.jsx**
- Add ResponsiveProvider context wrapper
- Import responsive context if available
- Update view state management for mobile nav
- Add mobile hamburger toggle state
- Pass responsive data to child components

**Changes**:
```javascript
// Add at top
import { useResponsive } from './context/ResponsiveProvider.jsx';

// In component
const responsive = useResponsive();
const [mobileNavOpen, setMobileNavOpen] = useState(false);

// Pass to Header
<Header 
  ...
  responsive={responsive}
  mobileNavOpen={mobileNavOpen}
  onToggleNav={() => setMobileNavOpen(!mobileNavOpen)}
/>

// Conditionally render SideNav or TabBar
{responsive.isMobile ? (
  <MobileTabBar active={view} onChange={handleViewChange} />
) : (
  <SideNav 
    ...
    isOpen={mobileNavOpen && responsive.isTablet}
  />
)}
```

**2. src/components/Header.jsx**
- Add hamburger menu button for mobile/tablet
- Responsive logo (full on desktop, icon-only on mobile)
- Responsive title positioning
- Status indicator positioning
- Adaptive padding

**Changes**:
```javascript
// Add responsive imports
import { ChevronDown, Menu, X } from 'lucide-react';
import { useResponsive } from '../context/ResponsiveProvider.jsx';

// Add to component
const responsive = useResponsive();
const [isMenuOpen, setIsMenuOpen] = useState(false);

// Conditional rendering
{responsive.isMobile ? (
  <button className="header__menu-toggle" onClick={onToggleNav}>
    <Menu size={24} />
  </button>
) : responsive.isTablet ? (
  <button className="header__menu-toggle" onClick={onToggleNav}>
    <Menu size={20} />
  </button>
) : null}

// Responsive status display
{responsive.isDesktop && <FullStatus />}
{responsive.isTablet && <MinimalStatus />}
```

**3. src/components/SideNav.jsx**
- Support responsive widths (280px standard, 70px collapsed, hidden on mobile)
- Responsive item font sizes
- Handle mobile nav state (visibility)
- Collapsible on tablet when not focused
- Animate transitions

**Changes**:
```javascript
// Responsive sidebar class application
<nav className={`sidebar ${responsive.isTablet ? 'sidebar--collapsed' : ''} ${mobileNavOpen ? 'sidebar--open' : ''}`}>
  // Content remains same, styling handles responsiveness
</nav>
```

**4. src/components/Workspace.jsx**
- Responsive padding (1.5rem desktop, 1rem tablet, 0.75rem mobile)
- Responsive title sizing
- Dynamic grid adjustments based on device
- Pass responsive context to child pages

**Changes**:
```javascript
const responsive = useResponsive();

<main className={`workspace workspace--${responsive.breakpoint}`}>
  {/* Children handle own responsive styling */}
</main>
```

**5. src/components/StatusBar.jsx**
- Responsive layout (flex wrap on mobile)
- Hide non-essential info on mobile
- Reposition elements for small screens
- Touch-friendly button sizing

**Changes**:
```javascript
const responsive = useResponsive();

// Conditional rendering based on breakpoint
{responsive.isDesktop && <FullStatusInfo />}
{responsive.isTablet && <TabletStatusInfo />}
{responsive.isMobile && <MobileStatusInfo />}
```

#### Page Components

**6. src/components/DashboardHome.jsx**
- Responsive hero section sizing
- Metric grid: 6 cols (desktop) → 3 cols (tablet) → 2 cols (mobile)
- Category section grid adjustments
- Responsive spacing & padding
- Typography scaling

**Changes**:
```javascript
const responsive = useResponsive();

// Hero responsive
<div className={`dashboard-home__hero dashboard-home__hero--${responsive.breakpoint}`}>

// Stats grid responsive
<div className="dashboard-home__stats" 
  style={{
    gridTemplateColumns: responsive.isMobile ? 'repeat(2, 1fr)' :
                        responsive.isTablet ? 'repeat(3, 1fr)' :
                        'repeat(6, 1fr)'
  }}
>

// Module categories
{GROUP_ORDER.map(group => (
  <div key={group} className={`module-category module-category--${responsive.breakpoint}`}>
```

**7. src/components/ModuleGrid.jsx**
- Responsive card grid (1-4 cols based on breakpoint)
- Touch-friendly card sizing
- Responsive typography
- Card metadata positioning

**Changes**:
```javascript
// Grid responsive via CSS class approach
<div className={`module-grid module-grid--${responsive.breakpoint}`}>
  {modules.map(mod => (
    <div className="module-card" key={mod.id}>
      {/* Content same, styling handles layout */}
    </div>
  ))}
</div>
```

**8. src/components/ModuleExecutor.jsx**
- Form panel responsive width (400px desktop, 100% mobile)
- Output panel responsive (side-by-side desktop, stacked mobile)
- Form fields full-width on mobile
- Buttons responsive sizing

**Changes**:
```javascript
const responsive = useResponsive();

<div className={`executor-panel__body executor-panel__body--${responsive.breakpoint}`}>
  <div className={`executor-panel__form executor-panel__form--${responsive.breakpoint}`}>
    {/* Form fields auto-responsive via CSS */}
  </div>
  <div className={`executor-panel__output executor-panel__output--${responsive.breakpoint}`}>
    {/* Output rendering with format toggles */}
  </div>
</div>
```

**9. src/components/InteractiveTerminal.jsx**
- Full-screen on mobile (with close button)
- Slide-up panel on tablet
- Resizable panel on desktop
- Responsive typography
- Touch-friendly controls

**Changes**:
```javascript
const responsive = useResponsive();

// Container responsive positioning
const terminalClasses = responsive.isMobile ? 'terminal--fullscreen' :
                       responsive.isTablet ? 'terminal--slideup' :
                       'terminal--panel';

<div className={`terminal-container ${terminalClasses}`}>
  {/* Terminal content */}
</div>
```

### 3.3 New Component Files to Create

**1. src/context/ResponsiveProvider.jsx**
Purpose: Central responsive state management  
Responsibility: Track viewport, expose breakpoint context

**File**:
```javascript
// Context hook + Provider component
// Tracks viewport size with ResizeObserver
// Provides: isMobile, isTablet, isDesktop, breakpoint, viewportWidth/Height
// Updates on resize with throttling (200ms)
```

**2. src/components/MobileTabBar.jsx**
Purpose: Bottom navigation for mobile devices  
Responsibility: Navigate between main views

**File**:
```javascript
// Fixed bottom bar (60px)
// Icons from lucide-react + labels
// 5 items: Home, Modules, Search, Settings, More
// Active state highlighting
// Touch-optimized hit targets
```

**3. src/components/OutputRenderer.jsx**
Purpose: Unified output display with format switching  
Responsibility: Render JSON, HTML, Markdown, Raw formats

**File**:
```javascript
// Format toggle buttons (JSON | HTML | Markdown | Raw)
// JSON view: syntax highlighting, scrollable
// HTML view: iframed, safe rendering
// Markdown view: converted HTML, table support
// Raw view: pre-formatted text
// Controls: Save, Download, Fullscreen, Clear
// Copy-to-clipboard functionality
```

**4. src/components/StatCard.jsx**
Purpose: Reusable metric/stat card component  
Responsibility: Consistent stat display across dashboards

**File**:
```javascript
// Props: icon, value, label, color, variant
// Responsive sizing
// Hover effects
// Optional trend indicator
// Accessible ARIA labels
```

**5. src/components/ResponsiveNav.jsx**
Purpose: Adaptive navigation wrapper  
Responsibility: Switch between SideNav and MobileTabBar

**File**:
```javascript
// Conditional rendering based on breakpoint
// Manages nav state (open/closed)
// Handles mobile nav close on item select
// Smooth transitions
```

**6. src/components/ResponsiveLayout.jsx**
Purpose: Main layout controller  
Responsibility: Coordinate header, nav, workspace, footer

**File**:
```javascript
// Children: Header, Nav, Workspace, Footer/StatusBar
// Manages whole-page responsive layout
// Handles nav toggle state
// Optional: Add drawer overlay for mobile nav
```

### 3.4 File Modification Summary Table

| File | Type | Changes | Priority |
|------|------|---------|----------|
| src/index.css | CSS | Refactor to modular structure | P0 |
| src/App.jsx | React | Add responsive context, mobile state | P0 |
| src/components/Header.jsx | React | Hamburger menu, responsive layout | P0 |
| src/components/SideNav.jsx | React | Responsive width, hide on mobile | P0 |
| src/components/Workspace.jsx | React | Responsive padding, pass context | P1 |
| src/components/StatusBar.jsx | React | Responsive layout, optional elements | P1 |
| src/components/DashboardHome.jsx | React | Responsive grid, typography | P1 |
| src/components/ModuleGrid.jsx | React | Responsive columns, card sizes | P1 |
| src/components/ModuleExecutor.jsx | React | Form/output responsive layout | P1 |
| src/components/InteractiveTerminal.jsx | React | Overlay responsiveness | P2 |
| src/components/ReportManager.jsx | React | Responsive table/list layout | P2 |
| src/index.html | HTML | Update viewport meta tag | P0 |
| src/context/ResponsiveProvider.jsx | New | Create responsive context | P0 |
| src/components/MobileTabBar.jsx | New | Create mobile navigation | P0 |
| src/components/OutputRenderer.jsx | New | Create output formatter | P1 |
| src/components/StatCard.jsx | New | Create stat card component | P1 |

---

## PART 4: RESPONSIVE COMPONENT SPECIFICATIONS

### 4.1 Header Component (Responsive)

**Desktop (lg+)**:
```
┌─────────────────────────────────────────┐
│ [Logo(40px)] JABBER RED TEAMING SUITE │ Engine Online · V3.5 · 50 modules │
└─────────────────────────────────────────┘
Height: 56px
Logo: Visible with text
Status: Full details shown
```

**Tablet (md)**:
```
┌─────────────────────────────────────────┐
│ ☰ JABBER RED TEAMING SUITE    🟢 Online │
└─────────────────────────────────────────┘
Height: 56px
Logo: Icon + abbreviated text
Status: Compact (dot + status)
Hamburger: Visible, toggles sidebar
```

**Mobile (xs-sm)**:
```
┌─────────────────────────────────────────┐
│ ☰  JABBER                      🟢 Online │
└─────────────────────────────────────────┘
Height: 48px
Logo: Icon only + single word
Status: Dot indicator only
Hamburger: Visible
```

**CSS Classes**:
```css
.app-header—responsive {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--spacing-responsive);
  background: var(--gradient-header);
  height: var(--header-height-responsive);
}

/* Responsive values */
@media (max-width: 768px) {
  --header-height-responsive: 48px;
  --spacing-responsive: 0.75rem;
}

@media (min-width: 1024px) {
  --header-height-responsive: 56px;
  --spacing-responsive: 1.25rem;
}

.header__logo-full { display: none; }
@media (min-width: 1024px) { .header__logo-full { display: block; } }

.header__logo-compact { display: block; }
@media (min-width: 1024px) { .header__logo-compact { display: none; } }
```

**Responsive Props**:
```javascript
<Header 
  responsive={{
    showFullTitle: isDesktop,
    logoSize: isMobile ? 32 : 40,
    statusDetails: isDesktop,
    menuVisible: !isDesktop
  }}
/>
```

### 4.2 Navigation Components

#### Sidebar (Tablet & Desktop)

**Desktop (lg+)**:
```
┌──────────────┐
│ [Logo 70x70] │
│              │
│ INTELLIGENCE │
│ • Recon      │
│ • Scanning   │
│              │
│ ACCESS       │
│ • Exploit    │
│ • Vuln Scan  │
│              │
│ PRIVILEGE    │
│ • Escalate   │
│              │
│ [User 70x70] │ (bottom)
└──────────────┘
Width: 280px
Items: Full label visible
Logo: Always visible
Hover effects: Full gradient
```

**Tablet (md)**:
```
┌──────┐
│ [L]  │ Intelligence: visible on hover/focus
│      │
│ [I]  │ (Icon tooltips)
│ [A]  │
│ [P]  │
│      │
│ [U]  │ (bottom)
└──────┘
Width: 70px (collapsed)
Items: Icons only
Labels: Tooltip on hover
Expandable: Slide out to 280px on interaction
```

**Mobile**: Hidden (tab bar only)

**CSS**:
```css
.sidebar {
  width: var(--sidebar-expanded);
  transition: width var(--transition-normal);
}

@media (max-width: 1024px) {
  .sidebar {
    width: var(--sidebar-collapsed);
  }
  
  .sidebar__item-label {
    display: none;
  }
  
  .sidebar:hover,
  .sidebar.sidebar--expanded {
    width: var(--sidebar-expanded);
  }
  
  .sidebar:hover .sidebar__item-label {
    display: inline;
  }
}

@media (max-width: 768px) {
  .sidebar {
    transform: translateX(-100%);
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    z-index: 200;
    height: 100vh;
  }
  
  .sidebar.sidebar--open {
    transform: translateX(0);
  }
}
```

#### Mobile Tab Bar (Mobile Only)

```
┌──────────────────────────────┐
│ 🏠  │ 📦  │ 🔍  │ ⚙️  │ ⋯  │
│ HOME│MOD │SRCH │SETTING│MORE
└──────────────────────────────┘
Height: 60px
Items: Icon + label
Active: Crimson background + white icon
Inactive: Steel icon, hover to light steel
Gap: Evenly spaced (flex 1)
Position: Fixed bottom, z-index 150
Touchable: 44px min height per item
```

**Implementation**:
```javascript
<MobileTabBar 
  items={[
    { icon: Home, label: 'HOME', view: 'dashboard' },
    { icon: Package, label: 'MODULES', view: 'category' },
    { icon: Search, label: 'SEARCH', view: 'search' },
    { icon: Settings, label: 'SETTINGS', view: 'settings' },
    { icon: MoreHorizontal, label: 'MORE', view: 'more' }
  ]}
  active={activeView}
  onChange={setActiveView}
/>
```

### 4.3 Dashboard Component (Responsive)

**Desktop (lg+)**:
```
┌─────────────────────────────────────────────────┐
│                   HERO SECTION                   │
│              JABBER RED TEAMING SUITE            │
│             Subtitle · Version · Status          │
└─────────────────────────────────────────────────┘

┌─────┬─────┬─────┬─────┬─────┬─────┐
│ 150 │ 12  │ 4   │ 10  │ 8   │ 19  │ (6 columns)
│ Mods│ Act │Criti│High │Med │ Cats│
└─────┴─────┴─────┴─────┴─────┴─────┘

INTELLIGENCE & PLANNING
├─ [Reconnaissance      ]
├─ [Scanning           ]
└─ [Social Engineering]

ACCESS & PENETRATION
├─ [Exploitation       ]
└─ [Web Assessment     ]
```

**Tablet (md)**:
```
┌──────────────────────────────────┐
│      JABBER SUITE (Compact)      │
│    Subtitle · Status             │
└──────────────────────────────────┘

┌──────┬──────┬──────┐
│ 150  │ 12   │ 4    │ (3 columns)
│ Mods │ Act  │Criti │
└──────┴──────┴──────┘

┌──────────────┬──────────────┐
│ Recon        │ Scanning     │ (2 columns, stacking)
├──────────────┼──────────────┤
│ Social Eng   │ Exploitation │
└──────────────┴──────────────┘
```

**Mobile (xs-sm)**:
```
┌──────────────┐
│ JABBER SUITE │
│ Status       │
└──────────────┘

┌──────┬──────┐
│ 150  │ 12   │ (2 columns)
│ Mods │ Act  │
└──────┴──────┘

[Reconnaissance]
  All modules listed, single column
[Scanning]
[Social Eng]
[Exploitation]
```

**CSS Grid System**:
```css
/* Desktop */
.dashboard-home__stats {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 1rem;
}

/* Tablet */
@media (max-width: 1200px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(3, 1fr);
  }
}

/* Mobile */
@media (max-width: 768px) {
  .dashboard-home__stats {
    grid-template-columns: repeat(2, 1fr);
    gap: 0.75rem;
  }
}

/* Module category grid */
.module-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 1rem;
}

@media (max-width: 768px) {
  .module-grid {
    grid-template-columns: 1fr;
  }
}
```

### 4.4 Module Card Component

**Card Specifications**:
```
┌────────────────────────────────┐
│ Module Name          [CRITICAL] │
├────────────────────────────────┤
│ Short description text wrapped  │
│ to maximum 3 lines with...      │
├────────────────────────────────┤
│ v1.2.3  @source/module          │
└────────────────────────────────┘

Min-width: 320px (enforced on mobile)
Max-width: 100% (fills container)
Aspect ratio: Auto (flexible height)
Padding: 1.25rem (desktop), 1rem (mobile)
Gap: 0.75rem (internal)
Border: 1px solid --border
Radius: 12px
Hover: Lift 2px, crimson border, glow shadow
Touch: Larger touch target, maintained hover effect
```

**Responsive Typography**:
```css
.module-card__name {
  font-size: 15px;      /* desktop/tablet */
  font-weight: 700;
  line-height: 1.3;
}

@media (max-width: 480px) {
  .module-card__name {
    font-size: 14px;
  }
}

.module-card__description {
  font-size: 12px;      /* all sizes same for consistency */
  line-height: 1.6;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.module-card__meta {
  font-size: 11px;
  flex-wrap: wrap;
  gap: 0.75rem;
}

@media (max-width: 480px) {
  .module-card__meta {
    font-size: 10px;
    gap: 0.5rem;
  }
}
```

### 4.5 Output Renderer Component

**Multi-Format Display**:
```
FORMAT TOGGLE ROW:
[JSON] [HTML] [MARKDOWN] [RAW]

CONTENT AREA:
┌─────────────────────────────────┐
│ Scrollable output display       │
│ Format-specific rendering       │
│ (JSON: syntax highlight         │
│  HTML: iframed                  │
│  MD: converted & rendered       │
│  RAW: plain pre-wrap)           │
└─────────────────────────────────┘

CONTROL ROW:
[SAVE] [DOWNLOAD] [FULLSCREEN] [CLEAR]
```

**Desktop Layout**: Horizontal toggle, full-width content, all controls visible  
**Tablet Layout**: Horizontal toggle, smaller content, abbreviated labels  
**Mobile Layout**: Vertical stack toggle, full-width content, icon-only controls

**CSS Structure**:
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
}

.output-renderer__format-toggle {
  display: flex;
  gap: 0.25rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-input);
  padding: 2px;
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
}

/* Mobile: Stack controls vertically */
@media (max-width: 768px) {
  .output-renderer__controls {
    flex-direction: column;
  }
  
  .output-renderer__toolbar {
    flex-direction: column;
  }
  
  .output-renderer__format-toggle {
    width: 100%;
    grid-template-columns: repeat(4, 1fr);
  }
}
```

### 4.6 Stat Card Component

**Variations**:

**Default Stat**:
```
┌────────────────────┐
│      [ICON]        │
│    150             │ (title/value)
│  Modules           │ (label)
└────────────────────┘
Center-aligned, icon at top
```

**Inline Stat**:
```
┌─────────────────────────────────┐
│ [ICON] 150 Modules              │
│        @dancan.tech             │
└─────────────────────────────────┘
Horizontal layout, left-aligned
```

**Responsive Props**:
```javascript
<StatCard
  icon={Package}
  value={150}
  label="Modules"
  variant={responsive.isMobile ? 'compact' : 'normal'}
  color="crimson"
  trend={+5}  // optional trend
/>
```

### 4.7 Form Component Responsiveness

**Form Layout Desktop**:
```
┌─────────────────────────────────────┐
│ INPUT LABEL                         │
│ [Input field: 100% width]           │
│ Help text                           │
│                                     │
│ OPTIONAL LABEL                      │
│ [Select dropdown: 100% width]       │
│                                     │
│ [Mode Segmented: 100% width]        │
│   [MODE A] [MODE B] [MODE C]        │
│                                     │
│            [EXECUTE BTN]            │
└─────────────────────────────────────┘
Single column, full-width fields
```

**Form Layout Mobile**:
```
┌──────────────────────┐
│ INPUT LABEL          │
│ [Input field: 100%]  │
│ Help text (smaller)  │
│                      │
│ OPT LABEL            │
│ [Select: 100%]       │
│                      │
│ [Mode Seg: 100%]     │
│   [A][B][C]          │
│                      │
│ [EXECUTE BTN: 100%]  │
└──────────────────────┘
Single column, touch-friendly 44px+ buttons
```

**CSS**:
```css
.form-group {
  margin-bottom: 1rem;
}

.form-group__input,
.form-group__select,
.form-group__textarea {
  width: 100%;
  padding: 0.5rem 0.75rem;
  min-height: 44px;  /* touch target */
}

@media (max-width: 768px) {
  .form-group__input,
  .form-group__select,
  .form-group__textarea {
    padding: 0.65rem 0.75rem;
    font-size: 16px;  /* prevent zoom on iOS */
  }
}

.mode-segmented {
  display: grid;
  width: 100%;
  grid-template-columns: repeat(auto-fit, minmax(60px, 1fr));
}

.mode-segmented__segment {
  padding: 0.5rem;
  min-height: 44px;  /* touch target */
}
```

---

## PART 5: IMPLEMENTATION PHASES & ROADMAP

### Phase 1: Foundation & Responsive Infrastructure (Week 1)
**Duration**: 2-3 days  
**Priority**: Critical path  
**Deliverables**: Breakpoint system, responsive context, CSS modularization

**Tasks**:
1. Create ResponsiveProvider context component
2. Modularize CSS into separate files
3. Add viewport tracking & throttled resize listener
4. Update index.html with proper viewport meta tag
5. Create responsive utility classes
6. Test breakpoint detection on various devices

**Testing Checklist**:
- [ ] ResponsiveProvider works on mount
- [ ] Resize listener triggers correctly
- [ ] No layout shift on viewport changes
- [ ] CSS imports in correct order
- [ ] No style conflicts between modules

**Files Modified**: 
- index.html, index.css (→ styles/*), App.jsx
- NEW: context/ResponsiveProvider.jsx

---

### Phase 2: Navigation Layer (Week 1, Days 2-3)
**Duration**: 2 days  
**Priority**: Critical path  
**Deliverables**: Mobile tab bar, responsive header, collapsible sidebar

**Tasks**:
1. Create MobileTabBar component
2. Update Header component with hamburger + responsive states
3. Update SideNav with collapse/expand behavior
4. Implement mobile nav state management in App
5. Add nav animation & transitions
6. Create ResponsiveNav wrapper component

**Testing Checklist**:
- [ ] Tab bar visible on mobile only
- [ ] Tab bar items clickable (44x44px min)
- [ ] Sidebar collapses on tablet
- [ ] Hamburger menu works
- [ ] Nav items highlight on active view
- [ ] Sidebar slides out smoothly on mobile
- [ ] Touch gestures work (if implementing swipe)

**Files Modified**: 
- App.jsx, Header.jsx, SideNav.jsx, StatusBar.jsx
- NEW: MobileTabBar.jsx, ResponsiveNav.jsx

---

### Phase 3: Layout & Spacing Changes (Week 2, Days 1-2)
**Duration**: 2 days  
**Priority**: High  
**Deliverables**: Responsive padding, gaps, and container sizing

**Tasks**:
1. Update Workspace with responsive padding
2. Adjust StatusBar layout for mobile
3. Responsive spacing utilities
4. Remove fixed widths from cards/panels
5. Test overflow handling on all breakpoints

**Testing Checklist**:
- [ ] No horizontal scroll on any device
- [ ] Content visible without clipping
- [ ] Proper padding on all sides
- [ ] Terminal overlay fits screen
- [ ] Safe area handling on notched devices

**Files Modified**: 
- Workspace.jsx, StatusBar.jsx, styles/responsive.css

---

### Phase 4: Dashboard Responsiveness (Week 2, Days 3-4)
**Duration**: 2 days  
**Priority**: High  
**Deliverables**: Responsive dashboard with grid system

**Tasks**:
1. Update DashboardHome stats grid (6→3→2 columns)
2. Responsive typography scaling
3. Mobile-optimized hero section
4. Category module grid adjustments
5. Create StatCard component
6. Test responsive images/icons

**Testing Checklist**:
- [ ] Stats display correctly on all breakpoints
- [ ] Hero section scales responsively
- [ ] Module categories stack properly on mobile
- [ ] Icons scale appropriately
- [ ] No content overflow
- [ ] Touch targets adequate

**Files Modified**: 
- DashboardHome.jsx, StatCard.jsx
- styles/dashboard.css

---

### Phase 5: Module Grid & Cards (Week 2, Day 5 / Week 3, Day 1)
**Duration**: 1.5 days  
**Priority**: High  
**Deliverables**: Responsive module cards and grid

**Tasks**:
1. Responsive module grid columns (4→2→1)
2. Card sizing responsiveness
3. Typography scaling on cards
4. Meta information layout on mobile
5. Touch hover effects
6. Responsive ModuleGrid component

**Testing Checklist**:
- [ ] Cards don't overflow containers
- [ ] Single column on mobile works
- [ ] Card text truncates elegantly
- [ ] Hover/active states work on touch
- [ ] Badges display properly

**Files Modified**: 
- ModuleGrid.jsx
- styles/components/cards.css

---

### Phase 6: Module Executor Panel (Week 3, Days 2-3)
**Duration**: 2 days  
**Priority**: High  
**Deliverables**: Responsive form + output layout

**Tasks**:
1. Form panel responsive width (400px→100%)
2. Output panel stacking (side/top based on device)
3. Form fields responsive sizing
4. Button sizing/spacing responsive
5. Output tabs responsive layout
6. Responsive form structure

**Testing Checklist**:
- [ ] Forms stack correctly on mobile
- [ ] Output readable on all devices
- [ ] Form inputs have 44px+ hit targets
- [ ] Buttons fit within screen width
- [ ] No overflow on small devices
- [ ] Terminal integration responsive

**Files Modified**: 
- ModuleExecutor.jsx
- styles/pages/executor.css

---

### Phase 7: Output Rendering System (Week 3, Days 4-5)
**Duration**: 2 days  
**Priority**: Medium  
**Deliverables**: Multi-format output display, controls

**Tasks**:
1. Create OutputRenderer component
2. JSON rendering with syntax highlighting
3. HTML rendering in iframe
4. Markdown parsing and display
5. Raw text output handling
6. Save/Download/Fullscreen controls
7. Format toggle UI

**Testing Checklist**:
- [ ] All 4 formats render correctly
- [ ] HTML renders safely in iframe
- [ ] JSON syntax highlighting works
- [ ] Download creates valid files
- [ ] Fullscreen mode works
- [ ] Mobile controls are accessible
- [ ] No JavaScript injection vulnerabilities

**Files Modified**: 
- NEW: OutputRenderer.jsx
- ModuleExecutor.jsx
- styles/pages/output.css

---

### Phase 8: Terminal & Advanced Components (Week 4, Days 1-2)
**Duration**: 2 days  
**Priority**: Medium  
**Deliverables**: Responsive terminal, report manager

**Tasks**:
1. Terminal responsive positioning (fullscreen/modal/panel)
2. Terminal controls responsive
3. ReportManager responsive layout
4. TargetProfiler responsive
5. Modal/overlay responsive handling
6. Responsive typography in terminal

**Testing Checklist**:
- [ ] Terminal usable on mobile
- [ ] Terminal doesn't hide content
- [ ] Terminal controls accessible
- [ ] Report tables responsive
- [ ] Modal positioning correct on all devices

**Files Modified**: 
- InteractiveTerminal.jsx, ReportManager.jsx, TargetProfiler.jsx
- styles/pages/terminal.css

---

### Phase 9: Refinement & Polish (Week 4, Days 3-5)
**Duration**: 3 days  
**Priority**: Medium  
**Deliverables**: Animation smoothness, transitions, final styling

**Tasks**:
1. Smooth transitions between breakpoints
2. Animation optimization for mobile
3. Hover state alternatives for touch
4. Safe area implementation for notched devices
5. Dark mode consistency
6. Accent color adjustments
7. Shadow/glow effects on mobile optimization

**Testing Checklist**:
- [ ] Transitions are smooth (60fps)
- [ ] No jank on resize
- [ ] Animation performance good on low-end devices
- [ ] Touch interactions feel responsive
- [ ] Dark theme consistent
- [ ] All colors meet accessibility standards

**Files Modified**: 
- styles/animations.css
- All component files (minor tweaks)

---

### Phase 10: Testing & Optimization (Week 5)
**Duration**: Full week  
**Priority**: Critical  
**Deliverables**: Cross-device testing, performance optimization

**Tasks**:
1. Device testing matrix (see below)
2. Performance audit (Lighthouse)
3. Accessibility audit (WCAG)
4. Cross-browser testing
5. Fix identified issues
6. Optimize CSS delivery
7. Documentation & handoff

**Testing Devices**:
- iPhone 12/13/14 (various sizes)
- iPad (multiple orientations)
- Android phones (Samsung, Pixel)
- Desktop Chrome/Firefox/Safari
- Electron window (min/max sizes)

**Performance Targets**:
- FCP < 1.5s
- LCP < 2.5s
- CLS < 0.1
- CSS bundle < 100KB (gzipped)
- No layout shift on navigation

**Files Modified**: 
- All (performance tuning)
- Documentation/README updates

---

## PART 6: COMPONENT SPECIFICATIONS & PATTERNS

### 6.1 Responsive Context Hook

**Usage Pattern**:
```javascript
import { useResponsive } from './context/ResponsiveProvider';

function MyComponent() {
  const responsive = useResponsive();
  
  return (
    <div className={`component component--${responsive.breakpoint}`}>
      {responsive.isMobile && <MobileLayout />}
      {responsive.isTablet && <TabletLayout />}
      {responsive.isDesktop && <DesktopLayout />}
    </div>
  );
}
```

**Available Data**:
```javascript
{
  isMobile: false,        // viewport < 768px
  isTablet: true,         // 768px ≤ viewport < 1024px
  isDesktop: false,       // viewport ≥ 1024px
  breakpoint: 'md',       // 'xs' | 'sm' | 'md' | 'lg' | 'xl'
  viewportWidth: 812,
  viewportHeight: 1024,
  canHover: true,         // false for touch-only devices
  orientation: 'landscape', // 'portrait' | 'landscape'
  isTouchDevice: false,
  safeAreaInset: {        // for notched devices
    top: 44,
    right: 0,
    bottom: 34,
    left: 0
  }
}
```

### 6.2 Responsive Sizing Utilities

**CSS Variable Approach**:
```css
:root {
  --container-max-width: 1440px;
  --gap-base: 1rem;
  --padding-responsive: 1.5rem;
}

@media (max-width: 1200px) {
  :root {
    --padding-responsive: 1.25rem;
  }
}

@media (max-width: 768px) {
  :root {
    --padding-responsive: 1rem;
    --gap-base: 0.75rem;
  }
}

@media (max-width: 480px) {
  :root {
    --padding-responsive: 0.75rem;
    --gap-base: 0.5rem;
  }
}
```

### 6.3 Responsive Component Template

**Standard Pattern**:
```javascript
import { useResponsive } from '../context/ResponsiveProvider';

function ResponsiveComponent({ children, title }) {
  const responsive = useResponsive();
  
  // Determine layout based on breakpoint
  const layout = {
    isMobile: responsive.breakpoint === 'xs' || responsive.breakpoint === 'sm',
    isTablet: responsive.breakpoint === 'md',
    isDesktop: responsive.breakpoint === 'lg' || responsive.breakpoint === 'xl'
  };
  
  return (
    <div 
      className={`component component--${responsive.breakpoint}`}
      role="region"
      aria-label={title}
    >
      {/* Conditional rendering */}
      {layout.isMobile && <MobileContent />}
      {layout.isTablet && <TabletContent />}
      {layout.isDesktop && <DesktopContent />}
    </div>
  );
}

export default ResponsiveComponent;
```

### 6.4 Mobile-First CSS Pattern

**Guideline**:
```css
/* BASE: Mobile first (all viewports) */
.component {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 0.75rem;
  font-size: 14px;
}

/* ENHANCED: Tablet and up */
@media (min-width: 768px) {
  .component {
    flex-direction: row;
    gap: 1rem;
    padding: 1.25rem;
  }
}

/* ENHANCED: Desktop and up */
@media (min-width: 1024px) {
  .component {
    gap: 1.5rem;
    padding: 1.5rem;
  }
}
```

**NOT** this approach:
```css
/* Anti-pattern: Desktop first */
.component {
  padding: 1.5rem;
}

@media (max-width: 1024px) {
  .component {
    padding: 1.25rem;
  }
}
```

### 6.5 Touch-Friendly Interactive Elements

**Minimum Touch Target**: 44px × 44px

```css
.button,
.link,
.input {
  min-height: 44px;
  min-width: 44px;
  padding: 0.5rem;
}

/* Prevent zoom on iOS input focus */
@media (max-width: 768px) {
  input,
  select,
  textarea {
    font-size: 16px !important;  /* Prevents zoom */
  }
}

/* Hover vs Active states */
@media (hover: hover) {
  /* Devices with hover support */
  .button:hover {
    background: var(--bg-elevated);
  }
}

@media (hover: none) {
  /* Touch-only devices */
  .button:active {
    background: var(--bg-elevated);
  }
}
```

### 6.6 Responsive Typography Scale

**Defined in tokens.css**:
```css
/* Headings */
h1 {
  font-size: clamp(24px, 5vw, 42px);  /* Fluid sizing */
  font-weight: 900;
  line-height: 1.1;
}

h2 {
  font-size: clamp(20px, 4vw, 28px);
  font-weight: 700;
  line-height: 1.2;
}

h3 {
  font-size: clamp(16px, 3vw, 20px);
  font-weight: 700;
  line-height: 1.3;
}

/* Body text */
body {
  font-size: clamp(13px, 2vw, 14px);
  line-height: 1.5;
}

small, .text-sm {
  font-size: clamp(11px, 1.5vw, 12px);
}
```

---

## PART 7: DESIGN TOKENS & SPECIFICATIONS

### 7.1 Typography Specifications

**Fonts**:
- Primary: Inter (UI elements, body text)
- Mono: JetBrains Mono (code, terminal, pre-formatted)

**Font Weights**: 300 (Light), 400 (Regular), 500 (Medium), 600 (SemiBold), 700 (Bold), 800 (ExtraBold), 900 (Black)

**Responsive Type Scale**:

| Element | Mobile | Tablet | Desktop |
|---------|--------|--------|---------|
| h1 | 24px | 32px | 42px |
| h2 | 18px | 22px | 28px |
| h3 | 14px | 16px | 20px |
| Body | 13px | 13px | 14px |
| Small | 11px | 11px | 12px |
| Tiny | 10px | 10px | 10px |
| Code | 11px | 12px | 12px |

**Line Heights**: 1.1 (headings), 1.5 (body), 1.6 (lists), 1.7 (long text)

### 7.2 Color System

**Semantic Colors**:
```
Primary Action: var(--crimson) #ff4444
Success: var(--emerald) #00ff41
Info: var(--ice-blue) #58a6ff
Warning: var(--amber) #d29922
Danger: var(--risk-critical) #f85149

Background Hierarchy:
Layer 0 (outer): var(--bg-primary) #0d1117
Layer 1 (panels): var(--bg-secondary) #161b22
Layer 2 (elevated): var(--bg-tertiary) #21262d
Layer 3 (cards): var(--bg-card) #161b2280

Text Hierarchy:
Primary: white / #ffffff
Secondary: var(--steel-light) #c9d1d9
Tertiary: var(--steel) #8b949e
Disabled: var(--steel) @ 40% opacity
```

### 7.3 Spacing System

**Base Unit**: 8px (1rem = 8px in CSS, 14px root for typography scale)

**Standard Spacing Scale**:
```
2px:   border widths, hairlines
4px:   0.5rem - small gaps, tight padding
8px:   1rem - standard padding/margin
12px:  1.5rem - medium spacing
16px:  2rem - large spacing
24px:  3rem - section spacing
32px:  4rem - major section gaps
```

**Responsive Spacing Adjustments**:
```
Mobile:  Reduce margins/padding by 25% (multiply by 0.75)
Tablet:  Reduce margins/padding by 10% (multiply by 0.9)
Desktop: Full spacing as designed
```

### 7.4 Border & Radius System

**Border Widths**:
```
1px: Standard borders, dividers
2px: Emphasis, active states
3px: Accent lines, highlights
```

**Border Radius Scale**:
```
sm:  4px   - small buttons, badges
md:  8px   - cards, inputs
lg:  12px  - panels, containers
xl:  16px  - hero sections
xxl: 24px  - large sections
```

**Border Colors**:
```
Default: var(--border) #30363d
Focus:   var(--border-focus) #58a6ff
Active:  var(--crimson) #ff4444
Subtle:  var(--border) @ 50% opacity
```

### 7.5 Shadow System

**Elevation Shadows**:
```
sm:  0 1px 2px rgba(0, 0, 0, 0.3)        /* Subtle */
md:  0 4px 12px rgba(0, 0, 0, 0.4)       /* Medium */
lg:  0 8px 30px rgba(0, 0, 0, 0.5)       /* Large */
glow-crimson: 0 0 20px rgba(255, 68, 68, 0.15)
glow-emerald: 0 0 20px rgba(0, 255, 65, 0.1)
```

**Mobile Adjustments**:
- Reduce shadow blur by 20%
- Keep small shadows, reduce large ones
- Use sparingly to preserve battery on OLED

### 7.6 Transition & Animation Specs

**Duration Scale**:
```
fast:   150ms (hover states, quick feedback)
normal: 300ms (standard transitions)
slow:   500ms (major layout changes)
```

**Easing Functions**:
```
ease: cubic-bezier(0.25, 0.46, 0.45, 0.94)
ease-in: cubic-bezier(0.42, 0, 1, 1)
ease-out: cubic-bezier(0, 0, 0.58, 1)
ease-in-out: cubic-bezier(0.42, 0, 0.58, 1)
```

**Common Animations**:
```
Fade In:      opacity 0→1, duration 300ms
Slide In:     translateX/Y, duration 300ms
Scale Bounce: scale with 10% overshoot, duration 400ms
Glow Pulse:   box-shadow intensity cycle, duration 2000ms
```

**Mobile Animations**:
- Disable non-essential animations (prefers-reduced-motion)
- Keep animations under 300ms
- Use GPU-accelerated properties (transform, opacity)

---

## PART 8: ACCESSIBILITY SPECIFICATIONS

### 8.1 WCAG 2.1 AA Compliance

**Color Contrast**:
- Text on background: 4.5:1 minimum (large text 3:1)
- All UI components: 3:1 for non-text contrast
- Exceptions: Decorative elements, logos

**Implementation Check**:
```css
/* Text contrast check (use contrast tool) */
color: var(--steel-light);        /* #c9d1d9 */
background: var(--bg-secondary);  /* #161b22 */
/* Ratio: 9.8:1 ✓ */
```

### 8.2 Keyboard Navigation

**Tab Order**:
- Header: Logo (non-interactive), Menu button (if visible)
- Navigation: Sidebar items or Tab bar items
- Main: Form fields, buttons, links
- Footer: Links, status

**Keyboard Shortcuts**:
```
? or h:     Show help
/, Ctrl+K:  Focus search
Escape:     Close modals/sidebars
Tab:        Navigate forward
Shift+Tab:  Navigate backward
Enter/Space: Activate buttons
Arrow keys: Navigate lists/menus
```

### 8.3 Touch Accessibility

**Minimum Touch Target**: 44×44px (Apple, Google, WCAG)

```css
button, a, input[type="checkbox"], input[type="radio"] {
  min-height: 44px;
  min-width: 44px;
}

/* Extra padding for safety zones */
@media (hover: none) {
  button {
    padding: 0.7rem 1.2rem;  /* Extra vertical padding */
  }
}
```

**Touch Labels**: 
- Visible labels for all interactive elements
- Icons + text when possible
- Size ≥ 12px at normal distance

### 8.4 Screen Reader Support

**ARIA Labels & Roles**:
```javascript
<nav role="navigation" aria-label="Main navigation">
  <button 
    aria-label="Toggle navigation menu"
    aria-expanded={isOpen}
    aria-controls="main-nav"
  >
    Menu
  </button>
</nav>

<main role="main" id="main-content">
  {/* Page content */}
</main>

<button 
  aria-label="Save output to file"
  aria-busy={isSaving}
>
  Save
</button>
```

### 8.5 Focus Management

```css
/* Visible focus indicators */
button:focus,
a:focus,
input:focus,
select:focus,
textarea:focus {
  outline: 2px solid var(--border-focus);
  outline-offset: 2px;
}

/* Remove default outline only if custom is provided */
*:focus-visible {
  outline: 2px solid var(--ice-blue);
  outline-offset: 2px;
}

/* Touch devices: softer focus indicator */
@media (hover: none) {
  *:focus-visible {
    outline: 3px solid var(--border-focus);
    outline-offset: 3px;
  }
}
```

### 8.6 Motion & Animation Accessibility

```css
/* Respect user's motion preferences */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

---

## PART 9: PERFORMANCE OPTIMIZATION

### 9.1 CSS Optimization

**Bundle Size Targets**:
```
Uncompressed: < 150KB
Gzipped:      < 40KB
```

**Optimization Strategies**:
1. Tree-shake unused CSS (PurgeCSS/Tailwind approach)
2. Minify CSS in production
3. Critical CSS inline (header + above-fold)
4. Deferred CSS loading for non-critical
5. No CSS duplicates across modules

**Code Split Approach**:
```
Critical (inline): base, reset, layout, typography: ~15KB
Deferred: components, animations, responsive: ~25KB
```

### 9.2 JavaScript Performance

**React Optimization**:
```javascript
// Memoization for expensive components
const ResponsiveCard = React.memo(CardComponent);

// Lazy load heavy components
const TerminalPanel = React.lazy(() => import('./InteractiveTerminal'));

// Use useCallback for handlers
const handleResize = useCallback(() => {
  // Responsive breakpoint update
}, []);

// Batch state updates
const [state, setState] = useState({
  width: 0,
  height: 0,
  breakpoint: 'md'
});
```

**Context Optimization**:
```javascript
// Split contexts by usage pattern
<ResponsiveProvider>
  <SessionProvider>
    <App />
  </SessionProvider>
</ResponsiveProvider>

// Use context selectors to prevent unnecessary renders
const isMobile = useResponsive().isMobile;  // Only subscribe to breakpoint change
```

### 9.3 Image & Asset Optimization

**Responsive Images**:
```html
<!-- Use srcset for different device densities -->
<img
  src="/logo-sm.png"
  srcset="/logo-sm.png 1x, /logo-sm@2x.png 2x"
  alt="JABBER Logo"
/>

<!-- Use picture element for art direction -->
<picture>
  <source media="(min-width: 1024px)" srcset="/hero-desktop.jpg">
  <source media="(min-width: 768px)" srcset="/hero-tablet.jpg">
  <img src="/hero-mobile.jpg" alt="Hero image">
</picture>
```

**Icon Optimization**:
- Use SVG for icons (scalable, small)
- Sprite sheets for multiple icons
- Lucide React for dynamic icons (tree-shakeable)

### 9.4 Network Optimization

**Code Splitting**:
```javascript
// Route-based splitting
const Dashboard = React.lazy(() => import('./DashboardHome'));
const ModuleExecutor = React.lazy(() => import('./ModuleExecutor'));

// Feature-based splitting
const OutputRenderer = React.lazy(() => import('./OutputRenderer'));
const TerminalPanel = React.lazy(() => import('./InteractiveTerminal'));
```

**Asset Delivery**:
- Preload critical fonts
- Prefetch likely next routes
- Compress all text assets (gzip)
- WebP images with fallbacks

---

## PART 10: TESTING STRATEGY & VALIDATION

### 10.1 Cross-Device Testing Matrix

**Mobile Phones**:
- iPhone SE (375px width)
- iPhone 12/13 (390px)
- iPhone 14 Pro Max (430px)
- Samsung Galaxy S10 (360px)
- Samsung Galaxy A52 (412px)
- Pixel 6 (412px)

**Tablets**:
- iPad Mini (768px)
- iPad Air (820px)
- iPad Pro 11" (834px)
- Samsung Galaxy Tab S8 (768px)

**Desktop**:
- 1024px width (minimum)
- 1280px (common)
- 1440px (premium)
- 1920px+ (large desktop)

**Orientations**:
- Portrait (all phones)
- Landscape (phones, tablets)
- Split-screen (tablets)

### 10.2 Browser Testing

**Desktop Browsers**:
- Chrome/Chromium (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions, macOS + iOS)
- Edge (latest)

**Mobile Browsers**:
- Safari on iOS (iPad, iPhone)
- Chrome on Android
- Firefox on Android
- Samsung Internet

### 10.3 Responsive Testing Checklist

**Navigation**:
- [ ] Header displays correctly on all breakpoints
- [ ] Mobile: Hamburger menu visible and functional
- [ ] Mobile: Tab bar visible, all items clickable
- [ ] Tablet: Sidebar collapses/expands smoothly
- [ ] Desktop: Full nav always visible
- [ ] Active states highlight correctly
- [ ] No horizontal scrolling

**Content**:
- [ ] Hero section scales responsively
- [ ] Stats cards grid: 6→3→2 columns correctly
- [ ] Module cards stack without overflow
- [ ] Text content readable (no clipping)
- [ ] Images responsive via imgs/srcset
- [ ] No content hidden unless intended

**Interactions**:
- [ ] Forms responsive, fields full-width on mobile
- [ ] Buttons ≥44px touch targets
- [ ] Terminal usable on mobile
- [ ] Output panels readable on all sizes
- [ ] Dropdowns/menus work on touch
- [ ] Scrolling smooth and performant

**Edge Cases**:
- [ ] iPad split-screen mode works
- [ ] Notched devices (safe areas)
- [ ] Landscape orientation handled
- [ ] Window resizing smooth (no jank)
- [ ] Maximized/minimized window sizes
- [ ] High zoom levels (200%+)

### 10.4 Performance Testing

**Lighthouse Audit**:
```
Target Scores:
- Performance: ≥ 80
- Accessibility: ≥ 90
- Best Practices: ≥ 90
- SEO: ≥ 90
```

**Core Web Vitals**:
```
LCP (Largest Contentful Paint):   < 2.5s
FID (First Input Delay):          < 100ms
CLS (Cumulative Layout Shift):    < 0.1
```

**Mobile Performance Budget**:
```
JS Bundle:   < 200KB (gzipped)
CSS Bundle:  < 50KB (gzipped)
Fonts:       < 100KB (gzipped)
Total:       < 350KB (gzipped)
```

### 10.5 Accessibility Testing

**Manual Testing**:
- [ ] Keyboard navigation works (Tab/Shift+Tab)
- [ ] Focus indicators visible
- [ ] All buttons/links have labels
- [ ] Form labels associated with inputs
- [ ] Color contrast ≥ 4.5:1
- [ ] No focus traps
- [ ] Modals manage focus correctly

**Automated Testing** (Tools):
- axe DevTools (Chrome extension)
- WAVE (WebAIM)
- Lighthouse accessibility audit
- Manual screen reader testing (VoiceOver, NVDA)

**Screen Readers**:
- VoiceOver (iOS, macOS)
- TalkBack (Android)
- NVDA (Windows)
- JAWS (Windows, testing)

---

## PART 11: DEPLOYMENT & MAINTENANCE

### 11.1 Build Configuration

**Vite Config Updates**:
```javascript
// vite.config.js
export default {
  build: {
    cssCodeSplit: true,           // Separate CSS by entry
    minify: 'terser',              // Minify JS
    sourcemap: true,               // For production debugging
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor': ['react', 'react-dom'],
          'vendor-ui': ['lucide-react'],
          'vendor-terminal': ['@xterm/xterm'],
        }
      }
    }
  }
}
```

### 11.2 CSS Preprocessing (Future)

**Optional Sass/SCSS Migration** (if performance requires):
```scss
// styles/_variables.scss
$breakpoints: (
  'xs': 320px,
  'sm': 480px,
  'md': 768px,
  'lg': 1024px,
  'xl': 1440px
);

@mixin respond-to($breakpoint) {
  @media (min-width: map-get($breakpoints, $breakpoint)) {
    @content;
  }
}

// Usage:
.component {
  padding: 0.75rem;
  
  @include respond-to('md') {
    padding: 1rem;
  }
}
```

### 11.3 Version Control & Releases

**Commit Strategy**:
```
feat: Add responsive layout system
fix: Fix mobile header height
refactor: Split CSS into modular structure
perf: Optimize responsive images
docs: Update responsive guidelines
```

**Release Versioning**:
```
v3.6.0: Responsive architecture (major feature)
v3.6.1: Responsive bug fixes
v3.6.2: Performance optimizations
v4.0.0: Next major release
```

### 11.4 Documentation

**README Updates**:
- Responsive architecture overview
- Device support matrix
- Testing procedures
- Contributing guidelines

**Developer Guide**:
- Responsive component patterns
- CSS module organization
- Breakpoint usage
- Common responsive patterns

**Design System Docs**:
- Color tokens
- Typography scale
- Spacing system
- Component library

---

## APPENDICES

### Appendix A: CSS Variable Reference

**Complete Token Listing** (see PART 7 for detailed specs)

### Appendix B: Component Wireframes

**Mobile Layout**:
```
[Header (48px)]
[Content scrollable]
[TabBar (60px)]
```

**Tablet Layout**:
```
[Header (56px)]
[70px sidebar | Content scrollable]
[StatusBar (50px)]
```

**Desktop Layout**:
```
[Header (56px)]
[280px sidebar | Content scrollable]
[StatusBar (50px)]
```

### Appendix C: Git Commit Messages

```
Initial responsive setup
- Add ResponsiveProvider context
- Create responsive CSS structure
- Update viewport meta tag

Responsive header and navigation
- Header hamburger for mobile/tablet
- Mobile tab bar implementation
- Collapsible sidebar

Dashboard responsive grid
- Stats card grid: 6→3→2 columns
- Responsive typography scaling
- Hero section adjustments

Module grid and cards
- Responsive card grid columns
- Touch-friendly card sizing
- Badge and meta responsive

Form and output responsive
- Form panel responsive width
- Output panel stacking
- Format toggle responsive layout

Terminal and advanced
- Terminal mobile fullscreen mode
- Report manager responsive
- Modal positioning fixes

Refinement and polish
- Animation smoothing
- Safe area implementation
- Final styling adjustments

Testing and optimization
- Cross-device testing
- Performance audit fixes
- Accessibility improvements
- Documentation finalization
```

---

## SUMMARY

This comprehensive implementation plan provides a structured, reusable approach to transforming the JRTS interface into a fully responsive, device-agnostic application. The plan balances technical specifications with practical implementation guidance, enabling consistent application of responsive principles across all components and ensuring quality delivery across mobile, tablet, and desktop platforms.

**Key Success Metrics**:
- ✓ Flawless rendering on all target devices
- ✓ No layout breaks or overflow
- ✓ Touch-friendly interactions (44px+ targets)
- ✓ Performance within budget (Lighthouse >80)
- ✓ WCAG 2.1 AA accessibility compliance
- ✓ Reusable patterns across all modules
- ✓ Smooth transitions between breakpoints
- ✓ Consistent design system

**Expected Timeline**: 4-5 weeks (10 phases × 3-5 days each)

**Team Size**: 1-2 developers (solo development feasible)

**Maintenance**: Ongoing CSS/responsive refinements during feature development
