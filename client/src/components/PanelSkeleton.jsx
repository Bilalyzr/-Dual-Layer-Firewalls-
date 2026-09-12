/**
 * PanelSkeleton — shimmer placeholder shown while a panel's first data load
 * is in flight (API cold start, network hiccup). Mirrors the reply-loader
 * sweep so loading states look consistent across the dashboard.
 */
export default function PanelSkeleton({ lines = 3, label = "loading" }) {
  return (
    <div className="rl-skel panel-skel" role="status" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => (
        <i key={i} style={{ width: `${88 - i * 18}%` }} />
      ))}
    </div>
  );
}
