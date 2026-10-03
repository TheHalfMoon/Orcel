// This script uses @vgpu/adapter-node, which requires native Vulkan support and a
// new-enough GLIBC. Run it inside the software-Vulkan Docker image when baking
// the static Orcel logo fallback:
//
//   docker run --rm \
//     -v /home/user/orcel-worktrees/orcel-hero-updates:/work \
//     -w /work/apps/docs \
//     -e VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
//     -e LIBGL_ALWAYS_SOFTWARE=1 \
//     -e ORCEL_LOGO_RENDER_THEME=dark \
//     -e ORCEL_LOGO_RENDER_WIDTH=1095 \
//     -e ORCEL_LOGO_RENDER_HEIGHT=348 \
//     -e ORCEL_LOGO_RENDER_PADDING=0 \
//     -e ORCEL_LOGO_RENDER_BLOOM=0 \
//     browser-webgpu-lab:native-vgpu-node \
//     bash -lc 'xvfb-run -a bash -lc "NODE_OPTIONS=--loader=./scripts/wgsl-node-loader.mjs ./node_modules/.bin/tsx scripts/render-orcel-5.ts"'
//
// The Docker image provides GLIBC 2.41, lavapipe/llvmpipe, libvulkan, and xvfb.
// Convert the generated tmp/orcel-5-renders/<run>/output.png to the desired
// public/orcel-5/fallback-<theme>.webp with ImageMagick from the same container.
// Set ORCEL_LOGO_RENDER_THEME=light|dark and ORCEL_LOGO_RENDER_WIDTH/HEIGHT when
// baking production fallbacks. Fallback images are content-only: render without
// bloom or padding, then place them inside the padded canvas box in CSS so the
// animated shader appears to "turn on" around the same logo geometry.
//
// QA / synthetic paint envs:
// - ORCEL_LOGO_RENDER_STAGE=glass|paint-debug|ascii|imprint|ascii/imprint
// - ORCEL_LOGO_RENDER_IMPRINT_PROGRESS=0..1 enables the front ASCII imprint path.
// - ORCEL_LOGO_PAINT_BLOB="x,y,radius,intensity[;...]" seeds soft paint blobs in paint-UV.
// - ORCEL_LOGO_PAINT_PATTERN=stripes|ramp|full seeds procedural paint.
// - ORCEL_LOGO_PAINT_STROKE="x0,y0,x1,y1,duration" simulates a moving brush stroke.
// - ORCEL_LOGO_PAINT_STROKE_MOVEMENT_GATED=false disables stroke movement gating for legacy sims.
// - ORCEL_LOGO_PAINT_STEPS=N runs N paint update frames before rendering.
// - ORCEL_LOGO_PAINT_DECAY_STEPS=N runs N additional inactive decay frames.
// - ORCEL_LOGO_PAINT_DECAY_PER_FRAME_120 sets linear paint removed per 120fps frame;
//   ORCEL_LOGO_PAINT_DECAY_RATE still overrides the equivalent per-second rate directly.
// - ORCEL_LOGO_PAINT_DIFFUSION, ORCEL_LOGO_PAINT_DIFFUSION_JITTER,
//   ORCEL_LOGO_PAINT_BRUSH_RADIUS, ORCEL_LOGO_PAINT_BRUSH_STRENGTH, and
//   ORCEL_LOGO_PAINT_DT override paint dynamics.
// - ORCEL_LOGO_ENV_YAW_TIME=seconds drives env yaw as seconds*0.15 for mobile rotation QA.
// - ORCEL_LOGO_RENDER_ENV_YAW=radians sets env yaw directly.
// Example: ORCEL_LOGO_RENDER_STAGE=glass ORCEL_LOGO_RENDER_IMPRINT_PROGRESS=1 \
//   ORCEL_LOGO_PAINT_BLOB="0.5,0.48,0.16,1" pnpm --dir apps/docs render:orcel-5

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createNodeAdapter } from "@vgpu/adapter-node";
import { App } from "@vgpu/core";
import { createOrcel5Renderer } from "../app/[lang]/(home)/components/orcel-logo-shader/render";
import { effectiveBloomStrength, readRenderConfig } from "./orcel-render/config";
import { readNoiseTimeEnv } from "./orcel-render/env";
import { loadMeshFromDisk } from "./orcel-render/load-mesh";
import { buildPaintSeed } from "./orcel-render/paint-fixtures";
import { maxFloat32 } from "./orcel-render/report";
import { renderDefaultViews } from "./orcel-render/views";

async function main() {
  const config = readRenderConfig();
  await mkdir(config.outDir, { recursive: true });
  const mesh = await loadMeshFromDisk(config.modelPath);
  const app = await App.create({ adapter: createNodeAdapter() });
  let renderer: ReturnType<typeof createOrcel5Renderer> | undefined;

  try {
    renderer = createOrcel5Renderer(app.device, config.format, mesh, {
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
            blob: process.env.ORCEL_LOGO_PAINT_BLOB ?? null,
            pattern: process.env.ORCEL_LOGO_PAINT_PATTERN ?? null,
            stroke: process.env.ORCEL_LOGO_PAINT_STROKE ?? null,
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
