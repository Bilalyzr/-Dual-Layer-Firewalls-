/**
 * Logo — the 3D "dual-layer" shield mark.
 *
 * Rendered as a layered, gradient-shaded SVG: dark-steel body, neon-cyan rim
 * light, recessed glass panel, a glowing AI core with dual defense chevrons,
 * and a specular gloss highlight. `idPrefix` keeps gradient/filter ids unique
 * when the logo is mounted more than once (e.g. topbar + boot loader).
 */
export default function Logo({ idPrefix = "dlf", className = "logo" }) {
  const p = idPrefix;
  return (
    <span className={className} aria-hidden="true">
      <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id={`${p}-steel`} x1="16" y1="4" x2="48" y2="60" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#4a6a9a" />
            <stop offset="0.45" stopColor="#1b2a52" />
            <stop offset="1" stopColor="#060c1e" />
          </linearGradient>
          <linearGradient id={`${p}-rim`} x1="32" y1="2" x2="32" y2="62" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#a8fdff" />
            <stop offset="0.5" stopColor="#00b8d4" />
            <stop offset="1" stopColor="#0a4a66" />
          </linearGradient>
          <radialGradient id={`${p}-glass`} cx="0.5" cy="0.3" r="0.78">
            <stop offset="0" stopColor="#0d2f4c" />
            <stop offset="1" stopColor="#04101f" />
          </radialGradient>
          <linearGradient id={`${p}-core`} x1="32" y1="20" x2="32" y2="46" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#c6feff" />
            <stop offset="1" stopColor="#00e5ff" />
          </linearGradient>
          <linearGradient id={`${p}-gloss`} x1="18" y1="6" x2="30" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#ffffff" stopOpacity="0.6" />
            <stop offset="1" stopColor="#ffffff" stopOpacity="0" />
          </linearGradient>
          <filter id={`${p}-glow`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.1" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* back layer — depth + the "dual" layer */}
        <path
          d="M32 5 L55 13 V30 C55 43.5 45.5 53.2 32 59 C18.5 53.2 9 43.5 9 30 V13 Z"
          fill="#020814"
          transform="translate(0 2.6)"
          opacity="0.9"
        />
        {/* neon rim */}
        <path d="M32 4 L56 12 V30 C56 44 46 54 32 60 C18 54 8 44 8 30 V12 Z" fill={`url(#${p}-rim)`} />
        {/* metallic body */}
        <path d="M32 7 L53 14 V30 C53 42 44 51 32 56.5 C20 51 11 42 11 30 V14 Z" fill={`url(#${p}-steel)`} />
        {/* recessed glass panel */}
        <path d="M32 11 L49 17 V30 C49 40 41.5 47.8 32 52.5 C22.5 47.8 15 40 15 30 V17 Z" fill={`url(#${p}-glass)`} />

        {/* emblem: AI core + dual defense chevrons */}
        <g filter={`url(#${p}-glow)`}>
          <circle cx="32" cy="24" r="3.6" fill={`url(#${p}-core)`} />
          <g stroke={`url(#${p}-core)`} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" fill="none">
            <path d="M22 30 L32 36 L42 30" />
            <path d="M22 38 L32 44 L42 38" opacity="0.65" />
          </g>
        </g>

        {/* specular gloss */}
        <path d="M32 8 L41 11.5 C33 14 25 22 23 36 C18.5 28 16.5 19 19 15 Z" fill={`url(#${p}-gloss)`} opacity="0.5" />
      </svg>
    </span>
  );
}
