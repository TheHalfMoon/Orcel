import type { NextConfig } from "next";
import { withEve } from "orcel/next";

const nextConfig: NextConfig = {};

export default withEve(nextConfig);
