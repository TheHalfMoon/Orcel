export const MOBILE_AUTO_ROTATE_SPEED = 0.15;

type OrcelPointerInteractionMode = {
  paintEnabled: boolean;
  autoRotateEnvYaw: boolean;
};

export function orcelPointerInteractionMode(isCoarsePointer: boolean): OrcelPointerInteractionMode {
  return {
    paintEnabled: !isCoarsePointer,
    autoRotateEnvYaw: isCoarsePointer,
  };
}

export function mobileAutoEnvYaw(timeSeconds: number) {
  return timeSeconds * MOBILE_AUTO_ROTATE_SPEED;
}
