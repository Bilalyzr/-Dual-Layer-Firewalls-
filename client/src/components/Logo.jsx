/**
 * Logo — the ORTHRUS mark.
 *
 * Orthrus, the two-headed guardian hound of Greek myth: one head watches
 * inbound prompts, the other watches outbound answers — the dual-layer
 * firewall rendered as a crest. Two angular wolf heads sit back-to-back
 * inside the shield, in the site's terracotta on warm charcoal, with
 * cream eyes and a soft glow. `idPrefix` keeps gradient ids unique when
 * the mark is mounted more than once (header + login).
 */
export default function Logo({ idPrefix = "dlf", className = "logo", size }) {
  const p = idPrefix;
  return (
    <span
      className={className}
      aria-hidden="true"
      style={size ? { width: size, height: size, display: "inline-flex" } : undefined}
    >
      <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style={{ width: "100%", height: "100%" }}>
        <defs>
          <linearGradient id={`${p}-terra`} x1="32" y1="6" x2="32" y2="58" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#e08d6d" />
            <stop offset="0.55" stopColor="#d97757" />
            <stop offset="1" stopColor="#b85f3f" />
          </linearGradient>
          <filter id={`${p}-glow`} x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="1.6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* shield — the firewall, warm charcoal with a terracotta rim */}
        <path
          d="M32 4 L56 12 V30 C56 44 46 54 32 60 C18 54 8 44 8 30 V12 Z"
          fill="#1f1e1d"
          stroke={`url(#${p}-terra)`}
          strokeWidth="2.5"
          strokeLinejoin="round"
        />

        {/* the two heads — left watches inbound, right watches outbound */}
        <g filter={`url(#${p}-glow)`}>
          <path
            d="M22 11 L29 11 L30.5 19 L27 21 L9 25.5 L26 31 L29 33 L27 45 L21.5 39 Z"
            fill={`url(#${p}-terra)`}
          />
          <path
            d="M42 11 L35 11 L33.5 19 L37 21 L55 25.5 L38 31 L35 33 L37 45 L42.5 39 Z"
            fill={`url(#${p}-terra)`}
          />
          {/* cream eyes — always watching */}
          <circle cx="23.5" cy="20.5" r="1.7" fill="#f4f3ee" />
          <circle cx="40.5" cy="20.5" r="1.7" fill="#f4f3ee" />
        </g>

        {/* central spine — the divide between the two layers */}
        <line x1="32" y1="12" x2="32" y2="46" stroke="#f4f3ee" strokeWidth="1.1" opacity="0.35" />
      </svg>
    </span>
  );
}
