import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';

const ResponsiveContext = createContext(null);

/**
 * Hook to access responsive context
 * @returns {Object} Responsive context with breakpoint and device info
 */
export function useResponsive() {
  const ctx = useContext(ResponsiveContext);
  if (!ctx) {
    throw new Error('useResponsive must be used within ResponsiveProvider');
  }
  return ctx;
}

/**
 * Provider component that tracks viewport size and breakpoints
 * Provides: isMobile, isTablet, isDesktop, breakpoint, viewportWidth/Height, etc.
 */
export function ResponsiveProvider({ children }) {
  const [viewport, setViewport] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 1024,
    height: typeof window !== 'undefined' ? window.innerHeight : 768,
  });

  const resizeTimeoutRef = useRef(null);

  // Calculate responsive state based on viewport width
  const getResponsiveState = useCallback((width) => {
    let breakpoint = 'xs';
    let isMobile = true;
    let isTablet = false;
    let isDesktop = false;

    if (width >= 1024) {
      breakpoint = width >= 1440 ? 'xl' : 'lg';
      isMobile = false;
      isDesktop = true;
    } else if (width >= 768) {
      breakpoint = 'md';
      isMobile = false;
      isTablet = true;
    } else if (width >= 480) {
      breakpoint = 'sm';
    }

    return {
      breakpoint,
      isMobile,
      isTablet,
      isDesktop,
      isSmallMobile: width < 480,
      isLargeDesktop: width >= 1440,
      canHover: window.matchMedia('(hover: hover)').matches,
      isTouchDevice: window.matchMedia('(hover: none)').matches,
      orientation: window.matchMedia('(orientation: portrait)').matches
        ? 'portrait'
        : 'landscape',
      safeAreaInset: {
        top: parseInt(
          getComputedStyle(document.documentElement).getPropertyValue(
            'env(safe-area-inset-top)'
          ) || 0
        ),
        right: parseInt(
          getComputedStyle(document.documentElement).getPropertyValue(
            'env(safe-area-inset-right)'
          ) || 0
        ),
        bottom: parseInt(
          getComputedStyle(document.documentElement).getPropertyValue(
            'env(safe-area-inset-bottom)'
          ) || 0
        ),
        left: parseInt(
          getComputedStyle(document.documentElement).getPropertyValue(
            'env(safe-area-inset-left)'
          ) || 0
        ),
      },
    };
  }, []);

  // Handle window resize with throttling
  const handleResize = useCallback(() => {
    if (resizeTimeoutRef.current) {
      clearTimeout(resizeTimeoutRef.current);
    }

    resizeTimeoutRef.current = setTimeout(() => {
      setViewport({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    }, 200); // Throttle resize events to 200ms
  }, []);

  // Setup resize listener
  useEffect(() => {
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      if (resizeTimeoutRef.current) {
        clearTimeout(resizeTimeoutRef.current);
      }
    };
  }, [handleResize]);

  // Calculate responsive state
  const responsiveState = getResponsiveState(viewport.width);

  // Combined context value
  const contextValue = {
    viewportWidth: viewport.width,
    viewportHeight: viewport.height,
    ...responsiveState,
  };

  return (
    <ResponsiveContext.Provider value={contextValue}>
      {children}
    </ResponsiveContext.Provider>
  );
}

export default ResponsiveProvider;
