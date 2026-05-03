# Pulsing Background (Image Watermark) Implementation

This document explains every file and every line of code responsible for the pulsing background image effect (brightening, dimming) in the UI. It also shows the exact code snippets that make it render and where each part is attached.

## Files involved

1. jabber-ui/src/index.css
   - Defines layout containers.
   - Creates the background image layer via .app-body::after.
   - Animates the opacity using @keyframes watermark-pulse.
   - Provides the sidebar width variable used to offset the watermark center.
2. jabber-ui/src/App.jsx
   - Renders the container element with class app-body. The pulsing layer is attached to this element via CSS.
3. jabber-ui/src/main.jsx
   - Imports index.css so the CSS (including the pulse animation) is loaded.
4. jabber-ui/index.html
   - Provides the #root mount point where React renders App (and thus app-body).
5. jabber-ui/publichttps://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png
   - The actual image displayed by the CSS background rule. It is a binary asset, not source code.

## Core CSS: layout + pulsing watermark

File: jabber-ui/src/index.css

```css
.app-container {
  display: flex;
  height: 100vh;
  flex-direction: column;
}

.app-body {
  display: flex;
  flex: 1;
  overflow: hidden;
  position: relative;
}

/* ===== Visual Identity: Centered Watermark ===== */
.app-body::after {
  content: '';
  position: fixed;
  top: 50%;
  left: calc(50% + var(--sidebar-width) / 2);
  transform: translate(-50%, -50%);
  width: min(60vw, 600px);
  height: min(60vw, 600px);
  background: url('https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png') center / contain no-repeat;
  opacity: 0.12;
  filter: blur(2px) drop-shadow(0 0 30px rgba(255, 68, 68, 0.05));
  pointer-events: none;
  z-index: 1;
  mask-image: radial-gradient(ellipse 65% 65% at center, black 25%, transparent 80%);
  -webkit-mask-image: radial-gradient(ellipse 65% 65% at center, black 25%, transparent 80%);
  animation: watermark-pulse 12s ease-in-out infinite;
}

@keyframes watermark-pulse {
  0%,
  100% {
    opacity: 5.0;
  }

  50% {
    opacity: 0.16;
  }
}
```

### How the effect works

- The pulsing image is not a DOM element. It is a CSS pseudo-element (::after) attached to .app-body.
- position: fixed makes it stay in the same spot while the app content scrolls.
- left: calc(50% + var(--sidebar-width) / 2) centers the watermark in the main content area, not the full window. The sidebar is on the left, so the watermark is shifted right by half the sidebar width.
- background: url('https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png') draws the image from jabber-ui/publichttps://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png.
- opacity is animated by watermark-pulse. Browsers clamp opacity to [0, 1], so the effective range is 1.0 (bright) down to 0.16 (dim) and back.
- filter adds blur and glow to soften the watermark.
- mask-image fades the edges so the image blends into the background.
- pointer-events: none prevents the layer from blocking clicks.
- z-index: 1 places it above the base page background but under most UI elements (the header uses z-index 100).

## Sidebar width used to center the watermark

File: jabber-ui/src/index.css

```css
:root {
  --sidebar-width: 280px;
}

@media (max-width: 1200px) {
  :root {
    --sidebar-width: 240px;
  }
}

@media (max-width: 768px) {
  :root {
    --sidebar-width: 100%;
    --header-height: 48px;
  }
}
```

### Why this matters

Because the watermark is centered using left: calc(50% + var(--sidebar-width) / 2), any change to --sidebar-width directly shifts the background image so it remains centered in the usable workspace area across breakpoints.

## Where the CSS attaches in the UI

File: jabber-ui/src/App.jsx

```jsx
return (
  <div className="app-container">
    <Header isConnected={isConnected} systemInfo={systemInfo} />
    <div className="app-body">
      <SideNav
        categories={categories}
        activeCategory={activeCategory}
        onCategorySelect={handleCategorySelect}
        onHomeClick={handleHomeClick}
        iconMap={CATEGORY_ICON_MAP}
      />
      <Workspace
        view={view}
        activeCategory={activeCategory}
        activeModule={activeModule}
        categories={categories}
        modules={activeCategory ? getModulesForCategory(activeCategory) : modules}
        allModules={modules}
        systemInfo={systemInfo}
        isConnected={isConnected}
        onModuleSelect={handleModuleSelect}
        onBack={handleBackToCategory}
        onCategorySelect={handleCategorySelect}
        onViewChange={handleViewChange}
        profilerReportIds={profilerReportIds}
      />
    </div>
    <StatusBar
      isConnected={isConnected}
      moduleCount={modules.length}
      categoryCount={categories.length}
    />
  </div>
);
```

### Why this matters

The watermark is defined as .app-body::after in CSS. That means the background image is attached to the div with class app-body shown above. If this class name changes, or if the container is removed, the watermark will disappear.

## How the CSS is loaded

File: jabber-ui/src/main.jsx

```jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

### Why this matters

The pulsing background lives in index.css, so importing './index.css' here is what actually applies the watermark styles globally.

## Where React mounts

File: jabber-ui/index.html

```html
<body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
</body>
```

### Why this matters

React renders the App component into #root, which creates .app-container and .app-body. Without this mount point, the watermark CSS would never attach to any element.

## The image asset itself

File: jabber-ui/publichttps://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png

This file is a binary image asset. It is referenced by the CSS background rule:

```css
background: url('https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png') center / contain no-repeat;
```

The web server (Vite dev server or built assets) serves https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png from the public folder, which is why the image appears.

## Rendering pipeline summary

1. index.html defines #root and loads /src/main.jsx.
2. main.jsx renders App and imports index.css.
3. App renders a div with class app-body.
4. index.css applies .app-body::after and defines watermark-pulse.
5. The browser paints a fixed background layer using jabber.png and animates its opacity forever.

If you want, I can add diagrams or trace how z-index and stacking contexts affect which UI elements appear above or below the watermark.