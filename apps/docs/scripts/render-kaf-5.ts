// This script uses @vgpu/adapter-node, which requires native Vulkan support and a
// new-enough GLIBC. Run it inside the software-Vulkan Docker image when baking
// the static Kaf logo fallback:
//
//   docker run --rm \
//     -v /home/user/kaf-worktrees/kaf-hero-updates:/work \
//     -w /work/apps/docs \
//     -e VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
//     -e LIBGL_ALWAYS_SOFTWARE=1 \
//     -e KAF_LOGO_RENDER_THEME=dark \
//     -e KAF_LOGO_RENDER_WIDTH=1095 \
//     -e KAF_LOGO_RENDER_HEIGHT=348 \
//     -e KAF_LOGO_RENDER_PADDING=0 \
//     -e KAF_LOGO_RENDER_BLOOM=0 \
//     browser-webgpu-lab:native-vgpu-node \
//     bash -lc 'xvfb-run -a bash -lc "NODE_OPTIONS=--loader=./scripts/wgsl-node-loader.mjs ./node_modules/.bin/tsx scripts/render-kaf-5.ts"'
//
// The Docker image provides GLIBC 2.41, lavapipe/llvmpipe, libvulkan, and xvfb.
// Convert the generated tmp/kaf-5-renders/<run>/output.png to the desired
// public/kaf-5/fallback-<theme>.webp with ImageMagick from the same container.
// Set KAF_LOGO_RENDER_THEME=light|dark and KAF_LOGO_RENDER_WIDTH/HEIGHT when
// baking production fallbacks. Fallback images are content-only: render without
// bloom or padding, then place them inside the padded canvas box in CSS so the
// animated shader appears to "turn on" around the same logo geometry.
//
// QA / synthetic paint envs:
// - KAF_LOGO_RENDER_STAGE=glass|paint-debug|ascii|imprint|ascii/imprint
// - KAF_LOGO_RENDER_IMPRINT_PROGRESS=0..1 enables the front ASCII imprint path.
// - KAF_LOGO_PAINT_BLOB="x,y,radius,intensity[;...]" seeds soft paint blobs in paint-UV.
// - KAF_LOGO_PAINT_PATTERN=stripes|ramp|full seeds procedural paint.
// - KAF_LOGO_PAINT_STROKE="x0,y0,x1,y1,duration" simulates a moving brush stroke.
// - KAF_LOGO_PAINT_STROKE_MOVEMENT_GATED=false disables stroke movement gating for legacy sims.
// - KAF_LOGO_PAINT_STEPS=N runs N paint update frames before rendering.
// - KAF_LOGO_PAINT_DECAY_STEPS=N runs N additional inactive decay frames.
// - KAF_LOGO_PAINT_DECAY_PER_FRAME_120 sets linear paint removed per 120fps frame;
//   KAF_LOGO_PAINT_DECAY_RATE still overrides the equivalent per-second rate directly.
// - KAF_LOGO_PAINT_DIFFUSION, KAF_LOGO_PAINT_DIFFUSION_JITTER,
//   KAF_LOGO_PAINT_BRUSH_RADIUS, KAF_LOGO_PAINT_BRUSH_STRENGTH, and
//   KAF_LOGO_PAINT_DT override paint dynamics.
// - KAF_LOGO_ENV_YAW_TIME=seconds drives env yaw as seconds*0.15 for mobile rotation QA.
// - KAF_LOGO_RENDER_ENV_YAW=radians sets env yaw directly.
// Example: KAF_LOGO_RENDER_STAGE=glass KAF_LOGO_RENDER_IMPRINT_PROGRESS=1 \
//   KAF_LOGO_PAINT_BLOB="0.5,0.48,0.16,1" pnpm --dir apps/docs render:kaf-5

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createNodeAdapter } from "@vgpu/adapter-node";
import { App } from "@vgpu/core";
import { createKaf5Renderer } from "../app/[lang]/(home)/components/kaf-logo-shader/render";
import { effectiveBloomStrength, readRenderConfig } from "./kaf-render/config";
import { readNoiseTimeEnv } from "./kaf-render/env";
import { loadMeshFromDisk } from "./kaf-render/load-mesh";
import { buildPaintSeed } from "./kaf-render/paint-fixtures";
import { maxFloat32 } from "./kaf-render/report";
import { renderDefaultViews } from "./kaf-render/views";

async function main() {
  const config = readRenderConfig();
  await mkdir(config.outDir, { recursive: true });
  const mesh = await loadMeshFromDisk(config.modelPath);
  const app = await App.create({ adapter: createNodeAdapter() });
  let renderer: ReturnType<typeof createKaf5Renderer> | undefined;

  try {
    renderer = createKaf5Renderer(app.device, config.format, mesh, {
      theme: config.theme,
      paddingRadius: config.paddingRadius,
      bloom: config.bloomEnabled,
    });

    const paintSeed = buildPaintSeed(config);
    const renderResult = await renderDefaultViews(
      renderer,
      app.device,
      config,
      config.defaultControls,
      paintSeed,
    );

    const log = {
      runId: config.runId,
      outDir: config.outDir,
      dimensions: {
        width: config.width,
        height: config.height,
        format: config.format,
        theme: config.theme,
        stage: config.renderStage,
        requestedStage: config.requestedRenderStage,
        dpr: config.dpr,
        envYaw: config.renderEnvYaw,
        envYawTime: config.renderEnvYawTime ?? null,
      },
      bloom: {
        enabled: config.bloomEnabled,
        runtimeRadius: config.bloomConstants.radius,
        radius: config.paddingRadius,
        strength: config.bloomEnabled
          ? effectiveBloomStrength(config, config.imprintProgress ?? 0)
          : 0,
        strengthOff: config.bloomConstants.strengthOff,
        strengthOn: config.bloomConstants.strengthOn,
        threshold: config.bloomConstants.threshold,
        logical: { width: config.logicalWidth, height: config.logicalHeight },
        padded: { width: config.width, height: config.height },
      },
      imprint:
        config.imprintProgress !== undefined
          ? {
              enabled: true,
              progress: config.imprintProgress,
              gridScaleMultiplier: config.imprintGridScaleMultiplier,
              glyphScale: config.imprintGlyphScale,
              noise: { time: readNoiseTimeEnv(), mouse: [0, 0] },
              stage: "front-glass-material-imprint",
            }
          : { enabled: false },
      paint: paintSeed
        ? {
            enabled: true,
            grid: { width: paintSeed.width, height: paintSeed.height },
            blob: process.env.KAF_LOGO_PAINT_BLOB ?? null,
            pattern: process.env.KAF_LOGO_PAINT_PATTERN ?? null,
            stroke: process.env.KAF_LOGO_PAINT_STROKE ?? null,
            steps: config.paintSteps,
            decaySteps: config.paintDecaySteps,
            dt: config.paintDt,
            decayPerFrame120: config.paintDecayPerFrame120,
            decayRate: config.paintDecayRate,
            diffusionRate: config.paintDiffusionRate,
            diffusionJitter: config.paintDiffusionJitter,
            brushRadius: config.paintBrushRadius,
            brushStrength: config.paintBrushStrength,
            seedMax: maxFloat32(paintSeed.values),
          }
        : { enabled: false },
      mesh: {
        vertices: mesh.positions.length / 3,
        triangles: mesh.indices.length / 3,
        bounds: mesh.bounds,
      },
      files: renderResult.files,
      output: renderResult.output,
    };

    const logWithOptionalBounds: typeof log & { bounds?: unknown } = log;
    if ("bounds" in renderResult) {
      logWithOptionalBounds.bounds = renderResult.bounds;
    }

    await writeFile(resolve(config.outDir, "log.json"), `${JSON.stringify(log, null, 2)}\n`);
    console.log(JSON.stringify(log, null, 2));

    if (
      log.output.nonBlack === 0 &&
      log.output.alpha === 0 &&
      !(
        config.renderStage === "paint-debug" &&
        (config.paintSteps > 0 || config.paintDecaySteps > 0)
      )
    )
      process.exitCode = 1;
  } finally {
    renderer?.dispose();
    app.device.destroy();
  }
}

await main();
