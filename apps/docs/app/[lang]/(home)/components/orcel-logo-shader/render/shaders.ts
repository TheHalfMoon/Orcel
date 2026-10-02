// Single shader import/compile registry; WGSL entry paths stay unchanged.
// INVARIANT: Pure move from render.ts; keep shader ABI, binding order, and pixel output unchanged.
// Imported by render/renderer.ts and re-exported only through render.ts facade.

import { Device } from "@vgpu/core";
import { compile } from "@vgpu/wgsl";
import glassBackWgsl from "../shaders/glass/back.wgsl";
import glassFrontWgsl from "../shaders/glass/front.wgsl";
import glassBackDepthWgsl from "../shaders/glass/back-depth.wgsl";
import orcelBloomBlurWgsl from "../shaders/bloom/blur.wgsl";
import orcelBloomCompositeWgsl from "../shaders/bloom/composite.wgsl";
import orcelLightCompositeWgsl from "../shaders/postprocess/light-composite.wgsl";
import orcelEnvBgWgsl from "../shaders/env/background.wgsl";
import renderTargetPreviewWgsl from "../shaders/debug/render-target-preview.wgsl";
import paintUpdateWgsl from "../shaders/paint/paint-update.wgsl";
import paintDebugWgsl from "../shaders/paint/paint-debug.wgsl";
import voronoiNoiseUpdateWgsl from "../shaders/paint/voronoi-noise-update.wgsl";

export function createShaders(device: Device) {
  return {
    glassBack: device.createShader(compile(glassBackWgsl)),
    glassFront: device.createShader(compile(glassFrontWgsl)),
    glassBackDepth: device.createShader(compile(glassBackDepthWgsl)),
    bloomBlur: device.createShader(compile(orcelBloomBlurWgsl)),
    bloomComposite: device.createShader(compile(orcelBloomCompositeWgsl)),
    lightComposite: device.createShader(compile(orcelLightCompositeWgsl)),
    envBg: device.createShader(compile(orcelEnvBgWgsl)),
    preview: device.createShader(compile(renderTargetPreviewWgsl)),
    paintUpdate: device.createShader(compile(paintUpdateWgsl)),
    paintDebug: device.createShader(compile(paintDebugWgsl)),
    voronoiNoiseUpdate: device.createShader(compile(voronoiNoiseUpdateWgsl)),
  };
}
