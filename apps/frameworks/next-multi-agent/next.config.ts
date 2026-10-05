import type { NextConfig } from "next";
import { withEve } from "@orcel/orcel/next";

const nextConfig: NextConfig = {};

export default withEve(nextConfig);
