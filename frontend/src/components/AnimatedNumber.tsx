import { useEffect, useRef, useState } from "react";

/**
 * Tweens between values so live metrics count up/down instead of snapping.
 */
export function AnimatedNumber({
  value,
  decimals = 0,
  duration = 700,
  className,
  suffix,
}: {
  value: number;
  decimals?: number;
  duration?: number;
  className?: string;
  suffix?: string;
}) {
  const [display, setDisplay] = useState(value);
  const cur = useRef(value);
  const raf = useRef(0);

  useEffect(() => {
    const from = cur.current;
    if (Math.abs(from - value) < 0.005) {
      cur.current = value;
      setDisplay(value);
      return;
    }
    const started = performance.now();
    const step = (now: number) => {
      const t = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      const next = from + (value - from) * eased;
      cur.current = next;
      setDisplay(next);
      if (t < 1) raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [value, duration]);

  return (
    <span className={className}>
      {display.toFixed(decimals)}
      {suffix}
    </span>
  );
}
