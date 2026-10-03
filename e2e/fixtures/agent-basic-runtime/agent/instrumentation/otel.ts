import { otel } from "@orcel/orcel/instrumentation/otel";

export default otel({ instrumentations: ["fetch"] });
