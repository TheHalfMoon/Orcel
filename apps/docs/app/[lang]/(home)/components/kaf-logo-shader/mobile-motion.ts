export const MOBILE_AUTO_ROTATE_SPEED = 0.15;

type KafPointerInteractionMode = {
  paintEnabled: boolean;
  autoRotateEnvYaw: boolean;
};

export function kafPointerInteractionMode(isCoarsePointer: boolean): KafPointerInteractionMode {
  return {
    paintEnabled: !isCoarsePointer,
    autoRotateEnvYaw: isCoarsePointer,
  };
}

export function mobileAutoEnvYaw(timeSeconds: number) {
  return timeSeconds * MOBILE_AUTO_ROTATE_SPEED;
}
