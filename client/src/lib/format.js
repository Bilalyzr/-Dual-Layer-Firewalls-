/**
 * format — shared display formatters.
 *
 * One time style across the whole dashboard (feed, tables, charts, meta
 * rows) instead of each component rolling its own toLocaleTimeString call.
 */

/** HH:MM:SS in the viewer's locale — for live feeds and chart axes. */
export const fmtTime = (ts) =>
  new Date(ts).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
