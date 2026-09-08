// vulnerable-libs.js
// A small, illustrative signature set of libraries with known-fixed versions.
// This is NOT exhaustive — it's a demo detector, not a replacement for
// tools like Retire.js or npm audit / Snyk.

(function () {
  function cmpVersions(a, b) {
    const pa = a.split(".").map(Number);
    const pb = b.split(".").map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const na = pa[i] || 0;
      const nb = pb[i] || 0;
      if (na !== nb) return na - nb;
    }
    return 0;
  }

  const SIGNATURES = [
    {
      name: "jQuery",
      detect: () => window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery,
      safeMin: "3.5.0",
      note: "Versions before 3.5.0 have known XSS issues in jQuery.htmlPrefilter.",
    },
    {
      name: "Lodash",
      detect: () => window._ && window._.VERSION,
      safeMin: "4.17.21",
      note: "Versions before 4.17.21 are affected by prototype-pollution issues.",
    },
    {
      name: "AngularJS",
      detect: () => window.angular && window.angular.version && window.angular.version.full,
      safeMin: "1.8.0",
      note: "AngularJS (1.x) is end-of-life; 1.8.0+ has the last official security fixes.",
    },
    {
      name: "Moment.js",
      detect: () => window.moment && window.moment.version,
      safeMin: "2.29.4",
      note: "Versions before 2.29.4 have a ReDoS vulnerability in its parser.",
    },
    {
      name: "Bootstrap",
      detect: () =>
        window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION,
      safeMin: "5.0.0",
      note: "Bootstrap 3/4 tooltip & data-attribute XSS issues were fixed in the 5.x line.",
    },
  ];

  function scanVulnerableLibs() {
    const found = [];
    for (const sig of SIGNATURES) {
      let version;
      try {
        version = sig.detect();
      } catch (e) {
        version = null;
      }
      if (!version) continue;
      const clean = String(version).replace(/^v/, "").split(/[-+]/)[0];
      const isOld = cmpVersions(clean, sig.safeMin) < 0;
      found.push({
        name: sig.name,
        version: clean,
        vulnerable: isOld,
        safeMin: sig.safeMin,
        note: sig.note,
      });
    }
    return found;
  }

  window.__secInspectorScanVulnerableLibs = scanVulnerableLibs;
})();
